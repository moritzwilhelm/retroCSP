function generateNonce(length = 16) {
    let chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let random_values = self.crypto.getRandomValues(new Uint8Array(length));
    let nonce = '';
    for (const rand of random_values) {
        nonce += chars[rand % chars.length];
    }
    return btoa(nonce);
}

// implements https://www.w3.org/TR/CSP3/#allow-all-inline
function allowsAllInlineScripts(sources) {
    let allowAllInline = false;
    for (const source of sources) {
        if (source.match(/^('nonce-[A-Za-z0-9+\/\-_]+={0,2}'|'sha(256|384|512)-[A-Za-z0-9+\/\-_]+={0,2}'|'strict-dynamic')$/i))
            return false;
        if (source.match(/^'unsafe-inline'$/i))
            allowAllInline = true;
    }
    return allowAllInline;
}

// check if set contains case-insensitive string
function hasCI(set, str) {
    for (const element of set)
        if (element.localeCompare(str, undefined, {sensitivity: 'accent'}) === 0)
            return true;
    return false;
}

function getScriptElementDirective(policy) {
    if ('script-src-elem' in policy)
        return 'script-src-elem';
    else if ('script-src' in policy)
        return 'script-src';
    else if ('default-src' in policy)
        return 'default-src';
    else
        return null;
}

function addNoncedInlineScript(responseText, nonce, code) {
    let script = `<script${nonce ? ` nonce="${nonce}"` : ''}>${code}</script>`;
    return responseText.replace('<head>', `<head>\n\t${script}`);
}

class StrictDynamicRetrofitter {
    static updateScriptElementDirective(policy, directive) {
        // remove everything except nonces, hashes and keyword sources
        for (const source of policy[directive])
            if (!source.match(/^('nonce-[A-Za-z0-9+\/\-_]+={0,2}'|'sha(256|384|512)-[A-Za-z0-9+\/\-_]+={0,2}'|'unsafe-inline'|'unsafe-eval'|'unsafe-hashes'|'strict-dynamic'|'report-sample')$/i))
                policy[directive].delete(source);
    }

    static retrofit(csp, responseText) {
        let strictDynamicNonce = null;
        for (const policy of csp.policies) {
            let scriptElementDirective = getScriptElementDirective(policy);
            if (scriptElementDirective && hasCI(policy[scriptElementDirective], "'strict-dynamic'")) {
                // modify CSP policy
                StrictDynamicRetrofitter.updateScriptElementDirective(policy, scriptElementDirective);
                // add strict-dynamic nonce to policy
                if (!strictDynamicNonce) {
                    strictDynamicNonce = generateNonce();
                }
                policy[scriptElementDirective].add(`'nonce-${strictDynamicNonce}'`);
            }
        }

        if (strictDynamicNonce) {
            // add retrofitting script
            let code = `(${StrictDynamicRetrofitter.retrofittingScript})(${JSON.stringify(strictDynamicNonce)});`;
            responseText = addNoncedInlineScript(responseText, csp.retrofittingNonce, code);
        }

        return responseText;
    }
}

// Safari does not support public static class fields (https://bugs.webkit.org/show_bug.cgi?id=194095)
StrictDynamicRetrofitter.retrofittingScript = function (strictDynamicNonce) {
    let original_createElement = document.createElement;
    document.createElement = function () {
        let element = original_createElement.apply(this, arguments);
        if (element.tagName === 'SCRIPT')
            element.nonce = strictDynamicNonce;
        return element;
    };

    let original_createElementNS = document.createElementNS;
    document.createElementNS = function () {
        let element = original_createElementNS.apply(this, arguments);
        if (element.tagName === 'SCRIPT')
            element.nonce = strictDynamicNonce;
        return element;
    };
};

class UnsafeHashesRetrofitter {
    static getUnsafeHashesDirective(policy) {
        if ('script-src-attr' in policy)
            return 'script-src-attr';
        else if ('script-src' in policy)
            return 'script-src';
        else if ('default-src' in policy)
            return 'default-src';
        else
            return null;
    }

    static retrofit(csp, responseText) {
        let hashSourceFound = false;
        let hashSourceLists = [];
        let restrictiveFormAction = false;
        for (const policy of csp.policies) {
            let unsafeHashesDirective = UnsafeHashesRetrofitter.getUnsafeHashesDirective(policy);
            if (unsafeHashesDirective) {
                if (allowsAllInlineScripts(policy[unsafeHashesDirective])) {
                    // any inline code allowed by this policy => ignore
                    continue;
                }

                let hashSources = [];
                for (const source of policy[unsafeHashesDirective]) {
                    let match = source.match(/^'(sha(256|384|512)-[A-Za-z0-9+\/\-_]+={0,2})'$/i);
                    if (match) {
                        hashSourceFound = true;
                        if (hasCI(policy[unsafeHashesDirective], "'unsafe-hashes'"))
                            hashSources.push(match[1]);
                    }
                }
                hashSourceLists.push(hashSources);
            }

            // check form-action directive
            let formActionDirective = 'form-action' in policy ? 'form-action' : 'navigate-to' in policy ? 'navigate-to' : null;
            if (formActionDirective && !hasCI(policy[formActionDirective], 'javascript:')) {
                restrictiveFormAction = true;
            }
        }
        // retrofit if CSP contains a hash source
        if (hashSourceFound) {
            // add retrofitting script
            let code = `(${UnsafeHashesRetrofitter.retrofittingScript})(${JSON.stringify(hashSourceLists)}, ${restrictiveFormAction});`;
            responseText = addNoncedInlineScript(responseText, csp.retrofittingNonce, code);

            // add inline hash computation library
            // https://code.google.com/archive/p/crypto-js/
            const cryptoJSCode = `var CryptoJS=function(h,s){var f={},t=f.lib={},g=function(){},j=t.Base={extend:function(a){g.prototype=this;var c=new g;a&&c.mixIn(a);c.hasOwnProperty("init")||(c.init=function(){c.$super.init.apply(this,arguments)});c.init.prototype=c;c.$super=this;return c},create:function(){var a=this.extend();a.init.apply(a,arguments);return a},init:function(){},mixIn:function(a){for(var c in a)a.hasOwnProperty(c)&&(this[c]=a[c]);a.hasOwnProperty("toString")&&(this.toString=a.toString)},clone:function(){return this.init.prototype.extend(this)}},q=t.WordArray=j.extend({init:function(a,c){a=this.words=a||[];this.sigBytes=c!=s?c:4*a.length},toString:function(a){return(a||u).stringify(this)},concat:function(a){var c=this.words,d=a.words,b=this.sigBytes;a=a.sigBytes;this.clamp();if(b%4)for(var e=0;e<a;e++)c[b+e>>>2]|=(d[e>>>2]>>>24-8*(e%4)&255)<<24-8*((b+e)%4);else if(65535<d.length)for(e=0;e<a;e+=4)c[b+e>>>2]=d[e>>>2];else c.push.apply(c,d);this.sigBytes+=a;return this},clamp:function(){var a=this.words,c=this.sigBytes;a[c>>>2]&=4294967295<<32-8*(c%4);a.length=h.ceil(c/4)},clone:function(){var a=j.clone.call(this);a.words=this.words.slice(0);return a},random:function(a){for(var c=[],d=0;d<a;d+=4)c.push(4294967296*h.random()|0);return new q.init(c,a)}}),v=f.enc={},u=v.Hex={stringify:function(a){var c=a.words;a=a.sigBytes;for(var d=[],b=0;b<a;b++){var e=c[b>>>2]>>>24-8*(b%4)&255;d.push((e>>>4).toString(16));d.push((e&15).toString(16))}return d.join("")},parse:function(a){for(var c=a.length,d=[],b=0;b<c;b+=2)d[b>>>3]|=parseInt(a.substr(b,2),16)<<24-4*(b%8);return new q.init(d,c/2)}},k=v.Latin1={stringify:function(a){var c=a.words;a=a.sigBytes;for(var d=[],b=0;b<a;b++)d.push(String.fromCharCode(c[b>>>2]>>>24-8*(b%4)&255));return d.join("")},parse:function(a){for(var c=a.length,d=[],b=0;b<c;b++)d[b>>>2]|=(a.charCodeAt(b)&255)<<24-8*(b%4);return new q.init(d,c)}},l=v.Utf8={stringify:function(a){try{return decodeURIComponent(escape(k.stringify(a)))}catch(c){throw Error("Malformed UTF-8 data");}},parse:function(a){return k.parse(unescape(encodeURIComponent(a)))}},x=t.BufferedBlockAlgorithm=j.extend({reset:function(){this._data=new q.init;this._nDataBytes=0},_append:function(a){"string"==typeof a&&(a=l.parse(a));this._data.concat(a);this._nDataBytes+=a.sigBytes},_process:function(a){var c=this._data,d=c.words,b=c.sigBytes,e=this.blockSize,f=b/(4*e),f=a?h.ceil(f):h.max((f|0)-this._minBufferSize,0);a=f*e;b=h.min(4*a,b);if(a){for(var m=0;m<a;m+=e)this._doProcessBlock(d,m);m=d.splice(0,a);c.sigBytes-=b}return new q.init(m,b)},clone:function(){var a=j.clone.call(this);a._data=this._data.clone();return a},_minBufferSize:0});t.Hasher=x.extend({cfg:j.extend(),init:function(a){this.cfg=this.cfg.extend(a);this.reset()},reset:function(){x.reset.call(this);this._doReset()},update:function(a){this._append(a);this._process();return this},finalize:function(a){a&&this._append(a);return this._doFinalize()},blockSize:16,_createHelper:function(a){return function(c,d){return(new a.init(d)).finalize(c)}},_createHmacHelper:function(a){return function(c,d){return(new w.HMAC.init(a,d)).finalize(c)}}});var w=f.algo={};return f}(Math);(function(h){for(var s=CryptoJS,f=s.lib,t=f.WordArray,g=f.Hasher,f=s.algo,j=[],q=[],v=function(a){return 4294967296*(a-(a|0))|0},u=2,k=0;64>k;){var l;a:{l=u;for(var x=h.sqrt(l),w=2;w<=x;w++)if(!(l%w)){l=!1;break a}l=!0}l&&(8>k&&(j[k]=v(h.pow(u,.5))),q[k]=v(h.pow(u,1/3)),k++);u++}var a=[],f=f.SHA256=g.extend({_doReset:function(){this._hash=new t.init(j.slice(0))},_doProcessBlock:function(c,d){for(var b=this._hash.words,e=b[0],f=b[1],m=b[2],h=b[3],p=b[4],j=b[5],k=b[6],l=b[7],n=0;64>n;n++){if(16>n)a[n]=c[d+n]|0;else{var r=a[n-15],g=a[n-2];a[n]=((r<<25|r>>>7)^(r<<14|r>>>18)^r>>>3)+a[n-7]+((g<<15|g>>>17)^(g<<13|g>>>19)^g>>>10)+a[n-16]}r=l+((p<<26|p>>>6)^(p<<21|p>>>11)^(p<<7|p>>>25))+(p&j^~p&k)+q[n]+a[n];g=((e<<30|e>>>2)^(e<<19|e>>>13)^(e<<10|e>>>22))+(e&f^e&m^f&m);l=k;k=j;j=p;p=h+r|0;h=m;m=f;f=e;e=r+g|0}b[0]=b[0]+e|0;b[1]=b[1]+f|0;b[2]=b[2]+m|0;b[3]=b[3]+h|0;b[4]=b[4]+p|0;b[5]=b[5]+j|0;b[6]=b[6]+k|0;b[7]=b[7]+l|0},_doFinalize:function(){var a=this._data,d=a.words,b=8*this._nDataBytes,e=8*a.sigBytes;d[e>>>5]|=128<<24-e%32;d[(e+64>>>9<<4)+14]=h.floor(b/4294967296);d[(e+64>>>9<<4)+15]=b;a.sigBytes=4*d.length;this._process();return this._hash},clone:function(){var a=g.clone.call(this);a._hash=this._hash.clone();return a}});s.SHA256=g._createHelper(f);s.HmacSHA256=g._createHmacHelper(f)})(Math);(function(a){var c=CryptoJS,d=c.lib,j=d.Base,f=d.WordArray,c=c.x64={};c.Word=j.extend({init:function(a,c){this.high=a;this.low=c}});c.WordArray=j.extend({init:function(c,d){c=this.words=c||[];this.sigBytes=d!=a?d:8*c.length},toX32:function(){for(var a=this.words,c=a.length,d=[],j=0;j<c;j++){var F=a[j];d.push(F.high);d.push(F.low)}return f.create(d,this.sigBytes)},clone:function(){for(var a=j.clone.call(this),c=a.words=this.words.slice(0),d=c.length,f=0;f<d;f++)c[f]=c[f].clone();return a}})})();(function(){function a(){return f.create.apply(f,arguments)}for(var c=CryptoJS,d=c.lib.Hasher,j=c.x64,f=j.Word,m=j.WordArray,j=c.algo,B=[a(1116352408,3609767458),a(1899447441,602891725),a(3049323471,3964484399),a(3921009573,2173295548),a(961987163,4081628472),a(1508970993,3053834265),a(2453635748,2937671579),a(2870763221,3664609560),a(3624381080,2734883394),a(310598401,1164996542),a(607225278,1323610764),a(1426881987,3590304994),a(1925078388,4068182383),a(2162078206,991336113),a(2614888103,633803317),a(3248222580,3479774868),a(3835390401,2666613458),a(4022224774,944711139),a(264347078,2341262773),a(604807628,2007800933),a(770255983,1495990901),a(1249150122,1856431235),a(1555081692,3175218132),a(1996064986,2198950837),a(2554220882,3999719339),a(2821834349,766784016),a(2952996808,2566594879),a(3210313671,3203337956),a(3336571891,1034457026),a(3584528711,2466948901),a(113926993,3758326383),a(338241895,168717936),a(666307205,1188179964),a(773529912,1546045734),a(1294757372,1522805485),a(1396182291,2643833823),a(1695183700,2343527390),a(1986661051,1014477480),a(2177026350,1206759142),a(2456956037,344077627),a(2730485921,1290863460),a(2820302411,3158454273),a(3259730800,3505952657),a(3345764771,106217008),a(3516065817,3606008344),a(3600352804,1432725776),a(4094571909,1467031594),a(275423344,851169720),a(430227734,3100823752),a(506948616,1363258195),a(659060556,3750685593),a(883997877,3785050280),a(958139571,3318307427),a(1322822218,3812723403),a(1537002063,2003034995),a(1747873779,3602036899),a(1955562222,1575990012),a(2024104815,1125592928),a(2227730452,2716904306),a(2361852424,442776044),a(2428436474,593698344),a(2756734187,3733110249),a(3204031479,2999351573),a(3329325298,3815920427),a(3391569614,3928383900),a(3515267271,566280711),a(3940187606,3454069534),a(4118630271,4000239992),a(116418474,1914138554),a(174292421,2731055270),a(289380356,3203993006),a(460393269,320620315),a(685471733,587496836),a(852142971,1086792851),a(1017036298,365543100),a(1126000580,2618297676),a(1288033470,3409855158),a(1501505948,4234509866),a(1607167915,987167468),a(1816402316,1246189591)],v=[],y=0;80>y;y++)v[y]=a();j=j.SHA512=d.extend({_doReset:function(){this._hash=new m.init([new f.init(1779033703,4089235720),new f.init(3144134277,2227873595),new f.init(1013904242,4271175723),new f.init(2773480762,1595750129),new f.init(1359893119,2917565137),new f.init(2600822924,725511199),new f.init(528734635,4215389547),new f.init(1541459225,327033209)])},_doProcessBlock:function(a,c){for(var d=this._hash.words,f=d[0],j=d[1],b=d[2],g=d[3],e=d[4],k=d[5],m=d[6],d=d[7],y=f.high,M=f.low,$=j.high,N=j.low,aa=b.high,O=b.low,ba=g.high,P=g.low,ca=e.high,Q=e.low,da=k.high,R=k.low,ea=m.high,S=m.low,fa=d.high,T=d.low,s=y,p=M,G=$,D=N,H=aa,E=O,W=ba,I=P,t=ca,q=Q,U=da,J=R,V=ea,K=S,X=fa,L=T,u=0;80>u;u++){var z=v[u];if(16>u)var r=z.high=a[c+2*u]|0,h=z.low=a[c+2*u+1]|0;else{var r=v[u-15],h=r.high,w=r.low,r=(h>>>1|w<<31)^(h>>>8|w<<24)^h>>>7,w=(w>>>1|h<<31)^(w>>>8|h<<24)^(w>>>7|h<<25),C=v[u-2],h=C.high,l=C.low,C=(h>>>19|l<<13)^(h<<3|l>>>29)^h>>>6,l=(l>>>19|h<<13)^(l<<3|h>>>29)^(l>>>6|h<<26),h=v[u-7],Y=h.high,A=v[u-16],x=A.high,A=A.low,h=w+h.low,r=r+Y+(h>>>0<w>>>0?1:0),h=h+l,r=r+C+(h>>>0<l>>>0?1:0),h=h+A,r=r+x+(h>>>0<A>>>0?1:0);z.high=r;z.low=h}var Y=t&U^~t&V,A=q&J^~q&K,z=s&G^s&H^G&H,ja=p&D^p&E^D&E,w=(s>>>28|p<<4)^(s<<30|p>>>2)^(s<<25|p>>>7),C=(p>>>28|s<<4)^(p<<30|s>>>2)^(p<<25|s>>>7),l=B[u],ka=l.high,ga=l.low,l=L+((q>>>14|t<<18)^(q>>>18|t<<14)^(q<<23|t>>>9)),x=X+((t>>>14|q<<18)^(t>>>18|q<<14)^(t<<23|q>>>9))+(l>>>0<L>>>0?1:0),l=l+A,x=x+Y+(l>>>0<A>>>0?1:0),l=l+ga,x=x+ka+(l>>>0<ga>>>0?1:0),l=l+h,x=x+r+(l>>>0<h>>>0?1:0),h=C+ja,z=w+z+(h>>>0<C>>>0?1:0),X=V,L=K,V=U,K=J,U=t,J=q,q=I+l|0,t=W+x+(q>>>0<I>>>0?1:0)|0,W=H,I=E,H=G,E=D,G=s,D=p,p=l+h|0,s=x+z+(p>>>0<l>>>0?1:0)|0}M=f.low=M+p;f.high=y+s+(M>>>0<p>>>0?1:0);N=j.low=N+D;j.high=$+G+(N>>>0<D>>>0?1:0);O=b.low=O+E;b.high=aa+H+(O>>>0<E>>>0?1:0);P=g.low=P+I;g.high=ba+W+(P>>>0<I>>>0?1:0);Q=e.low=Q+q;e.high=ca+t+(Q>>>0<q>>>0?1:0);R=k.low=R+J;k.high=da+U+(R>>>0<J>>>0?1:0);S=m.low=S+K;m.high=ea+V+(S>>>0<K>>>0?1:0);T=d.low=T+L;d.high=fa+X+(T>>>0<L>>>0?1:0)},_doFinalize:function(){var a=this._data,c=a.words,d=8*this._nDataBytes,f=8*a.sigBytes;c[f>>>5]|=128<<24-f%32;c[(f+128>>>10<<5)+30]=Math.floor(d/4294967296);c[(f+128>>>10<<5)+31]=d;a.sigBytes=4*c.length;this._process();return this._hash.toX32()},clone:function(){var a=d.clone.call(this);a._hash=this._hash.clone();return a},blockSize:32});c.SHA512=d._createHelper(j);c.HmacSHA512=d._createHmacHelper(j)})();(function(){var a=CryptoJS,c=a.x64,d=c.Word,j=c.WordArray,c=a.algo,f=c.SHA512,c=c.SHA384=f.extend({_doReset:function(){this._hash=new j.init([new d.init(3418070365,3238371032),new d.init(1654270250,914150663),new d.init(2438529370,812702999),new d.init(355462360,4144912697),new d.init(1731405415,4290775857),new d.init(2394180231,1750603025),new d.init(3675008525,1694076839),new d.init(1203062813,3204075428)])},_doFinalize:function(){var a=f._doFinalize.call(this);a.sigBytes-=16;return a}});a.SHA384=f._createHelper(c);a.HmacSHA384=f._createHmacHelper(c)})();(function(a){var m=CryptoJS,r=m.lib,f=r.Base,g=r.WordArray,m=m.x64={};m.Word=f.extend({init:function(a,p){this.high=a;this.low=p}});m.WordArray=f.extend({init:function(l,p){l=this.words=l||[];this.sigBytes=p!=a?p:8*l.length},toX32:function(){for(var a=this.words,p=a.length,f=[],q=0;q<p;q++){var G=a[q];f.push(G.high);f.push(G.low)}return g.create(f,this.sigBytes)},clone:function(){for(var a=f.clone.call(this),p=a.words=this.words.slice(0),g=p.length,q=0;q<g;q++)p[q]=p[q].clone();return a}})})();(function(){function a(){return g.create.apply(g,arguments)}for(var m=CryptoJS,r=m.lib.Hasher,f=m.x64,g=f.Word,l=f.WordArray,f=m.algo,p=[a(1116352408,3609767458),a(1899447441,602891725),a(3049323471,3964484399),a(3921009573,2173295548),a(961987163,4081628472),a(1508970993,3053834265),a(2453635748,2937671579),a(2870763221,3664609560),a(3624381080,2734883394),a(310598401,1164996542),a(607225278,1323610764),a(1426881987,3590304994),a(1925078388,4068182383),a(2162078206,991336113),a(2614888103,633803317),a(3248222580,3479774868),a(3835390401,2666613458),a(4022224774,944711139),a(264347078,2341262773),a(604807628,2007800933),a(770255983,1495990901),a(1249150122,1856431235),a(1555081692,3175218132),a(1996064986,2198950837),a(2554220882,3999719339),a(2821834349,766784016),a(2952996808,2566594879),a(3210313671,3203337956),a(3336571891,1034457026),a(3584528711,2466948901),a(113926993,3758326383),a(338241895,168717936),a(666307205,1188179964),a(773529912,1546045734),a(1294757372,1522805485),a(1396182291,2643833823),a(1695183700,2343527390),a(1986661051,1014477480),a(2177026350,1206759142),a(2456956037,344077627),a(2730485921,1290863460),a(2820302411,3158454273),a(3259730800,3505952657),a(3345764771,106217008),a(3516065817,3606008344),a(3600352804,1432725776),a(4094571909,1467031594),a(275423344,851169720),a(430227734,3100823752),a(506948616,1363258195),a(659060556,3750685593),a(883997877,3785050280),a(958139571,3318307427),a(1322822218,3812723403),a(1537002063,2003034995),a(1747873779,3602036899),a(1955562222,1575990012),a(2024104815,1125592928),a(2227730452,2716904306),a(2361852424,442776044),a(2428436474,593698344),a(2756734187,3733110249),a(3204031479,2999351573),a(3329325298,3815920427),a(3391569614,3928383900),a(3515267271,566280711),a(3940187606,3454069534),a(4118630271,4000239992),a(116418474,1914138554),a(174292421,2731055270),a(289380356,3203993006),a(460393269,320620315),a(685471733,587496836),a(852142971,1086792851),a(1017036298,365543100),a(1126000580,2618297676),a(1288033470,3409855158),a(1501505948,4234509866),a(1607167915,987167468),a(1816402316,1246189591)],y=[],q=0;80>q;q++)y[q]=a();f=f.SHA512=r.extend({_doReset:function(){this._hash=new l.init([new g.init(1779033703,4089235720),new g.init(3144134277,2227873595),new g.init(1013904242,4271175723),new g.init(2773480762,1595750129),new g.init(1359893119,2917565137),new g.init(2600822924,725511199),new g.init(528734635,4215389547),new g.init(1541459225,327033209)])},_doProcessBlock:function(a,f){for(var h=this._hash.words,g=h[0],n=h[1],b=h[2],d=h[3],c=h[4],j=h[5],l=h[6],h=h[7],q=g.high,m=g.low,r=n.high,N=n.low,Z=b.high,O=b.low,$=d.high,P=d.low,aa=c.high,Q=c.low,ba=j.high,R=j.low,ca=l.high,S=l.low,da=h.high,T=h.low,v=q,s=m,H=r,E=N,I=Z,F=O,W=$,J=P,w=aa,t=Q,U=ba,K=R,V=ca,L=S,X=da,M=T,x=0;80>x;x++){var B=y[x];if(16>x)var u=B.high=a[f+2*x]|0,e=B.low=a[f+2*x+1]|0;else{var u=y[x-15],e=u.high,z=u.low,u=(e>>>1|z<<31)^(e>>>8|z<<24)^e>>>7,z=(z>>>1|e<<31)^(z>>>8|e<<24)^(z>>>7|e<<25),D=y[x-2],e=D.high,k=D.low,D=(e>>>19|k<<13)^(e<<3|k>>>29)^e>>>6,k=(k>>>19|e<<13)^(k<<3|e>>>29)^(k>>>6|e<<26),e=y[x-7],Y=e.high,C=y[x-16],A=C.high,C=C.low,e=z+e.low,u=u+Y+(e>>>0<z>>>0?1:0),e=e+k,u=u+D+(e>>>0<k>>>0?1:0),e=e+C,u=u+A+(e>>>0<C>>>0?1:0);B.high=u;B.low=e}var Y=w&U^~w&V,C=t&K^~t&L,B=v&H^v&I^H&I,ha=s&E^s&F^E&F,z=(v>>>28|s<<4)^(v<<30|s>>>2)^(v<<25|s>>>7),D=(s>>>28|v<<4)^(s<<30|v>>>2)^(s<<25|v>>>7),k=p[x],ia=k.high,ea=k.low,k=M+((t>>>14|w<<18)^(t>>>18|w<<14)^(t<<23|w>>>9)),A=X+((w>>>14|t<<18)^(w>>>18|t<<14)^(w<<23|t>>>9))+(k>>>0<M>>>0?1:0),k=k+C,A=A+Y+(k>>>0<C>>>0?1:0),k=k+ea,A=A+ia+(k>>>0<ea>>>0?1:0),k=k+e,A=A+u+(k>>>0<e>>>0?1:0),e=D+ha,B=z+B+(e>>>0<D>>>0?1:0),X=V,M=L,V=U,L=K,U=w,K=t,t=J+k|0,w=W+A+(t>>>0<J>>>0?1:0)|0,W=I,J=F,I=H,F=E,H=v,E=s,s=k+e|0,v=A+B+(s>>>0<k>>>0?1:0)|0}m=g.low=m+s;g.high=q+v+(m>>>0<s>>>0?1:0);N=n.low=N+E;n.high=r+H+(N>>>0<E>>>0?1:0);O=b.low=O+F;b.high=Z+I+(O>>>0<F>>>0?1:0);P=d.low=P+J;d.high=$+W+(P>>>0<J>>>0?1:0);Q=c.low=Q+t;c.high=aa+w+(Q>>>0<t>>>0?1:0);R=j.low=R+K;j.high=ba+U+(R>>>0<K>>>0?1:0);S=l.low=S+L;l.high=ca+V+(S>>>0<L>>>0?1:0);T=h.low=T+M;h.high=da+X+(T>>>0<M>>>0?1:0)},_doFinalize:function(){var a=this._data,f=a.words,h=8*this._nDataBytes,g=8*a.sigBytes;f[g>>>5]|=128<<24-g%32;f[(g+128>>>10<<5)+30]=Math.floor(h/4294967296);f[(g+128>>>10<<5)+31]=h;a.sigBytes=4*f.length;this._process();return this._hash.toX32()},clone:function(){var a=r.clone.call(this);a._hash=this._hash.clone();return a},blockSize:32});m.SHA512=r._createHelper(f);m.HmacSHA512=r._createHmacHelper(f)})();(function(){var h=CryptoJS,j=h.lib.WordArray;h.enc.Base64={stringify:function(b){var e=b.words,f=b.sigBytes,c=this._map;b.clamp();b=[];for(var a=0;a<f;a+=3)for(var d=(e[a>>>2]>>>24-8*(a%4)&255)<<16|(e[a+1>>>2]>>>24-8*((a+1)%4)&255)<<8|e[a+2>>>2]>>>24-8*((a+2)%4)&255,g=0;4>g&&a+.75*g<f;g++)b.push(c.charAt(d>>>6*(3-g)&63));if(e=c.charAt(64))for(;b.length%4;)b.push(e);return b.join("")},parse:function(b){var e=b.length,f=this._map,c=f.charAt(64);c&&(c=b.indexOf(c),-1!=c&&(e=c));for(var c=[],a=0,d=0;d<e;d++)if(d%4){var g=f.indexOf(b.charAt(d-1))<<2*(d%4),h=f.indexOf(b.charAt(d))>>>6-2*(d%4);c[a>>>2]|=(g|h)<<24-8*(a%4);a++}return j.create(c,a)},_map:"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="}})();`;
            responseText = addNoncedInlineScript(responseText, csp.retrofittingNonce, cryptoJSCode);
        }

        return responseText;
    }
}

// Safari does not support public static class fields (https://bugs.webkit.org/show_bug.cgi?id=194095)
UnsafeHashesRetrofitter.retrofittingScript = function (hashSourceLists, restrictiveFormAction) {
    let functionID = 0;
    let retrofittingNonce = document.currentScript.nonce;

    function defineGlobalFunction(code) {
        let functionDefinition = document.createElement('script');
        let functionName = `globalFunction${functionID++}`;
        functionDefinition.innerText = `function ${functionName}(event){${code}}`;
        functionDefinition.nonce = retrofittingNonce;
        document.head.prepend(functionDefinition);
        return window[functionName];
    }

    function computeHash(algorithm, value) {
        switch (algorithm.toLowerCase()) {
            case 'sha256':
                return CryptoJS.SHA256(value).toString(CryptoJS.enc.Base64);
            case 'sha384':
                return CryptoJS.SHA384(value).toString(CryptoJS.enc.Base64);
            case 'sha512':
                return CryptoJS.SHA512(value).toString(CryptoJS.enc.Base64);
        }
    }

    // implements Step 5 & 6 of https://www.w3.org/TR/CSP3/#match-element-to-source-list
    function isHashSourceMatching(list, source, digests) {
        for (const hashSource of list) {
            const [algorithm, expected] = hashSource.split('-');
            if (!(algorithm in digests))
                digests[algorithm] = computeHash(algorithm, source);
            if (digests[algorithm] === expected)
                return true;
        }
        return false;
    }

    function isAllowedScript(code) {
        let digests = {};
        for (const hashSourceList of hashSourceLists) {
            if (!isHashSourceMatching(hashSourceList, code, digests))
                return false;
        }
        return true;
    }

    function handleInlineEventHandlerMutation(element, attribute) {
        if (attribute.match(/^on[a-z]+$/)) {
            if (element[attribute])
                element[attribute] = null;
            if (isAllowedScript(element.getAttribute(attribute))) {
                element[attribute] = function (event) {
                    // call inline code
                    defineGlobalFunction(element.getAttribute(attribute))(event);
                };
            }
        }
    }

    function handleJSUrlMutation(element, attribute) {
        switch (element.tagName) {
            case 'A':
                if (attribute === 'href' && element.hasAttribute('href') && element.getAttribute('href').match(/^javascript:/i)) {
                    let oldOnClickEvent = element.onclick;
                    element.onclick = function (event) {
                        event.preventDefault();
                        if (oldOnClickEvent)
                            oldOnClickEvent(event);
                    };
                    if (isAllowedScript(element.getAttribute('href')) || isAllowedScript(element.getAttribute('href').slice(11))) {
                        let onClickEvent = element.onclick;
                        element.onclick = function (event) {
                            onClickEvent(event);
                            // execute code in href attribute
                            defineGlobalFunction(element.getAttribute('href').slice(11))(event);
                        };
                    }
                }
                break;
            case 'FRAME':
                if (attribute === 'src' && element.hasAttribute('src') && element.getAttribute('src').match(/^javascript:/i)) {
                    if (isAllowedScript(element.getAttribute('src')) || isAllowedScript(element.getAttribute('src').slice(11))) {
                        let iframe = document.createElement('iframe');
                        let iframeScript = `<scr` + `ipt nonce="${retrofittingNonce}">${element.getAttribute('src').slice(11)}</scr` + `ipt>`;
                        iframe.setAttribute('srcdoc', iframeScript);
                        element.parentNode.insertBefore(iframe, element);
                        element.parentNode.removeChild(element);
                    } else {
                        element.removeAttribute('src');
                    }
                }
                break;
            case 'IFRAME':
                if (attribute === 'src' && element.hasAttribute('src') && element.getAttribute('src').match(/^javascript:/i)) {
                    if (isAllowedScript(element.getAttribute('src')) || isAllowedScript(element.getAttribute('src').slice(11))) {
                        let iframeScript = `<scr` + `ipt nonce="${retrofittingNonce}">${element.getAttribute('src').slice(11)}</scr` + `ipt>`;
                        element.setAttribute('srcdoc', iframeScript);
                    }
                    element.removeAttribute('src');
                }
                break;
            case 'FORM':
                if (attribute === 'action' && element.hasAttribute('action') && element.getAttribute('action').match(/^javascript:/i)) {
                    let oldOnSubmitEvent = element.onsubmit;
                    element.onsubmit = function (event) {
                        event.preventDefault();
                        if (oldOnSubmitEvent)
                            oldOnSubmitEvent(event);
                    };
                    if (!restrictiveFormAction) {
                        if (isAllowedScript(element.getAttribute('action')) || isAllowedScript(element.getAttribute('action').slice(11))) {
                            let onSubmitEvent = element.onsubmit;
                            element.onsubmit = function (event) {
                                onSubmitEvent(event);
                                // execute code in action attribute
                                defineGlobalFunction(element.getAttribute('action').slice(11))(event);
                            };
                        }
                    }
                }
                break;
        }
    }

    function mutator(mutationRecords) {
        for (const record of mutationRecords) {
            if (record.type === "childList") {
                for (const node of record.addedNodes) {
                    // nodeType 1 corresponds to Element
                    if (node.nodeType === 1) {
                        for (const attribute of node.attributes) {
                            handleInlineEventHandlerMutation(node, attribute.name);
                        }
                        // assures that inline event handler is retrofitted before modifying it (event.preventDefault)
                        for (const attribute of node.attributes) {
                            handleJSUrlMutation(node, attribute.name);
                        }
                    }
                }
            } else if (record.type === "attributes") {
                handleInlineEventHandlerMutation(record.target, record.attributeName);
                handleJSUrlMutation(record.target, record.attributeName);
            }
        }
    }

    new MutationObserver(mutator).observe(document.documentElement, {
        subtree: true,
        childList: true,
        attributes: true
    });

    // hook window.open
    let original_windowOpen = window.open;
    window.open = function () {
        if (!arguments[0].match(/^javascript:/i))
            return original_windowOpen.apply(this, arguments);

        if (isAllowedScript(arguments[0]) || isAllowedScript(arguments[0].slice(11))) {
            let newWindow = original_windowOpen('');
            let scriptTag = newWindow.document.createElement('script');
            scriptTag.nonce = retrofittingNonce;
            scriptTag.innerText = arguments[0].slice(11);
            newWindow.document.body.appendChild(scriptTag);
            return newWindow;
        }
        return null;
    };
};

class NavigateToRetrofitter {
    static retrofit(csp, responseText) {
        let navigateToDirectives = [];
        for (const policy of csp.policies) {
            if ('navigate-to' in policy) {
                if (!('form-action' in policy)) {
                    policy['form-action'] = new Set(policy['navigate-to']);
                }
                navigateToDirectives.push(Array.from(policy['navigate-to']));
            }
        }

        let matches = responseText.matchAll(/<!--.*?-->|(<meta[^>]+?http-equiv="refresh"[^>]*>)/ig);
        for (const match of matches) {
            if (match[1]) {
                let cspMatch = match[1].match(/content="([^"]+)"/i);
                if (cspMatch && !cspMatch[1].match(/^javascript:/i))
                    responseText = responseText.replace(match[0], match[0].replace("content", "refresh-target"));
            }
        }

        if (navigateToDirectives.length) {
            // add retrofitting script
            let code = `(${NavigateToRetrofitter.retrofittingScript})(${JSON.stringify(navigateToDirectives)});`;
            responseText = addNoncedInlineScript(responseText, csp.retrofittingNonce, code);
        }

        return responseText;
    }
}

// Safari does not support public static class fields (https://bugs.webkit.org/show_bug.cgi?id=194095)
NavigateToRetrofitter.retrofittingScript = function (navigateToDirectives) {
    // determines port based on scheme (https://url.spec.whatwg.org/#default-port)
    function getDefaultPort(scheme) {
        switch (scheme) {
            case "ftp:":
                return "21";
            case "file:":
                return null;
            case "ws:":
            case "http:":
                return "80";
            case "wss:":
            case "https:":
                return "443";
            default:
                return "";
        }
    }

    // does a case-insensitive compare of a and b
    function equalsCI(a, b) {
        if (typeof a === 'string' && typeof b === 'string')
            return a.localeCompare(b, undefined, {sensitivity: 'accent'}) === 0;
        else
            return a === b;
    }

    function parseHostSrc(expression) {
        let host = expression.match(/^(([A-Za-z][A-Za-z0-9+\-.]*:)\/\/)?(\*|(\*\.)?[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*)(:([0-9]+|\*))?(\/(([A-Za-z0-9-._~]|%[A-Fa-f0-9]{2}|[!$&'()*+,=]|[:@])+(\/([A-Za-z0-9-._~]|%[A-Fa-f0-9]{2}|[!$&'()*+,=]|[:@])*)*)?)?$/);
        if (!host)
            return null;
        return {
            schemePart: host[2] ? host[2].slice(0, -1) : null,
            hostPart: host[3],
            portPart: host[7] = host[7] ? host[7] : null,
            pathPart: host[8]
        };
    }

    // implements https://www.w3.org/TR/CSP3/#match-schemes
    function isSchemePartMatching(a, b) {
        return (equalsCI(a, b) ||
            a.match(/^http$/i) && b.match(/^https$/i) ||
            a.match(/^ws$/i) && b.match(/^(ws|https?)$/i) ||
            a.match(/^wss$/i) && b.match(/^https$/i));
    }

    function isIPAdress(host) {
        return host.match(/([0-9]|[1-9][0-9]|1[0-9]{2}|2[1-4][0-9]|25[0-5])(\.[0-9]|[1-9][0-9]|1[0-9]{2}|2[1-4][0-9]|25[0-5]){3}/);
    }

    // implements https://www.w3.org/TR/CSP3/#match-hosts
    function isHostPartMatching(a, b) {
        if (a.startsWith("*"))
            return new RegExp(`^${[...a.slice(1)].reverse().join("")}`, "i").test([...b].reverse().join(""));
        if (!equalsCI(a, b))
            return false;
        if (a === "127.0.0.1")
            return true;
        return !isIPAdress(a);
    }

    // implements https://www.w3.org/TR/CSP3/#match-ports
    function isPortPartMatching(a, b, scheme) {
        if (!a)
            return b === "" || b === getDefaultPort(scheme);
        if (a === "*")
            return true;
        if (a === b)
            return true;
        if (!b)
            return a === getDefaultPort(scheme);
        return false;
    }

    // implements https://www.w3.org/TR/CSP3/#match-paths
    function isPathPartMatching(a, b) {
        if (!a)
            return true;
        if (a === "/" && !b)
            return true;
        let exactMatch = !a.endsWith("/");
        let pathListA = a.split("/");
        let pathListB = b.split("/");
        if (pathListA.length > pathListB.length)
            return false;
        if (exactMatch && pathListA.length !== pathListB.length)
            return false;
        if (!exactMatch)
            pathListA.pop();
        for (let pieceA of pathListA) {
            let pieceB = pathListB.shift();
            if (decodeURIComponent(pieceA) !== decodeURIComponent(pieceB))
                return false;
        }
        return true;
    }

    // implements https://www.w3.org/TR/CSP3/#match-url-to-source-expression
    function isUrlMatchingExpression(url, expression, origin = location.origin) {
        try {
            origin = new URL(origin);
        } catch (TypeError) {
            return false;
        }

        if (expression === "*") {
            if (url.protocol.match(/^(ftp|https?):$/i) || equalsCI(url.protocol, origin.protocol))
                return true;
        }

        let schemeSrcMatch = expression.match(/^([A-Za-z][A-Za-z0-9+\-.]*):$/);
        if (schemeSrcMatch)
            return isSchemePartMatching(schemeSrcMatch[1], url.protocol.slice(0, -1));

        let hostSrc = parseHostSrc(expression);
        if (hostSrc) {
            if (!url.hostname)
                return false;
            if (hostSrc.schemePart && !isSchemePartMatching(hostSrc.schemePart, url.protocol.slice(0, -1)))
                return false;
            if (!hostSrc.schemePart && !isSchemePartMatching(origin.protocol.slice(0, -1), url.protocol.slice(0, -1)))
                return false;
            if (!isHostPartMatching(hostSrc.hostPart, url.hostname))
                return false;
            if (!isPortPartMatching(hostSrc.portPart, url.port, url.protocol))
                return false;
            return !(hostSrc.pathPart && !isPathPartMatching(hostSrc.pathPart, url.pathname));

        }

        if (expression.match(/^'self'$/i)) {
            if (equalsCI(origin.origin, url.origin))
                return true;
            if (equalsCI(origin.host, url.host) && (url.protocol.match(/^(https|wss):$/i) || origin.protocol.match(/^http$/i)))
                return true;
        }
        return false;
    }

    // implements https://www.w3.org/TR/CSP3/#match-url-to-source-list
    function isUrlMatchingSourceSet(url, sources) {
        if (sources.size === 0)
            return false;
        if (sources.size === 1 && sources.values().next().match(/^'none'$/i))
            return false;
        for (const expression of sources) {
            if (isUrlMatchingExpression(url, expression))
                return true;
        }
        return false;
    }

    function isAllowedNavigationTarget(url) {
        for (const sources of navigateToDirectives) {
            if (!(isUrlMatchingSourceSet(url, sources)))
                return false;
        }
        return true;
    }

    function handleUrlMutation(element, attribute) {
        switch (element.tagName) {
            case 'A':
                if (attribute === "href" && element.hasAttribute('href') && !element.getAttribute('href').match(/^javascript:/i)) {
                    let oldOnClickEvent = element.onclick;
                    element.onclick = function (event) {
                        event.preventDefault();
                        if (oldOnClickEvent)
                            oldOnClickEvent(event);
                    };

                    let url;
                    try {
                        url = new URL(element.getAttribute('href'), location.origin);
                    } catch (TypeError) {
                        break;
                    }

                    if (isAllowedNavigationTarget(url)) {
                        let onClickEvent = element.onclick;
                        element.onclick = function (event) {
                            onClickEvent(event);
                            // initiate navigation
                            location.href = url.toString();
                        };
                    }
                }
                break;
            case 'META':
                if (attribute === "http-equiv" && element.hasAttribute('http-equiv') && element.getAttribute('http-equiv').match(/^refresh$/i)) {
                    // find Service Worker marked attribute
                    let match = element.hasAttribute('refresh-target') ? element.getAttribute("refresh-target").match(/^(\d+);url=(.+)$/i) : null;
                    if (match) {
                        let url;
                        try {
                            url = new URL(match[2], location.origin);
                        } catch (TypeError) {
                            // bad URL => ignore
                            break;
                        }

                        if (isAllowedNavigationTarget(url)) {
                            // initiate navigation after n seconds
                            setTimeout(function () {
                                location.href = url.toString();
                            }, parseInt(match[1]) * 1000);
                        }

                        // remove meta-tag redirection
                        element.parentNode.removeChild(element);
                    }
                }
                break;
        }
    }

    function mutator(mutationRecords) {
        for (const record of mutationRecords) {
            if (record.type === "childList") {
                for (const node of record.addedNodes) {
                    // nodeType 1 corresponds to Element
                    if (node.nodeType === 1) {
                        for (const attribute of node.attributes)
                            handleUrlMutation(node, attribute.name);
                    }
                }
            } else if (record.type === "attributes") {
                handleUrlMutation(record.target, record.attributeName);
            }
        }
    }

    new MutationObserver(mutator).observe(document.documentElement, {
        subtree: true,
        childList: true,
        attributes: true
    });

    // hook window.open
    let original_windowOpen = window.open;
    window.open = function () {
        if (arguments[0] === "" || arguments[0].match(/^javascript:/i))
            return original_windowOpen.apply(this, arguments);

        try {
            var url = new URL(arguments[0], location.origin);
        } catch (TypeError) {
            return null;
        }
        if (isAllowedNavigationTarget(url)) {
            return original_windowOpen.apply(this, arguments);
        }

        return null;
    };
};

const RETROFITTERS = [
    StrictDynamicRetrofitter,
    UnsafeHashesRetrofitter,
    NavigateToRetrofitter,
];

class CSP {
    constructor(str) {
        this.policies = this.parseCSP(str);
        this.retrofittingNonce = this.createRetrofittingNonce();
    }

    parseCSP(csp) {
        let policies = [];
        for (const policyString of csp.split(',')) {
            let policy = {};
            for (const token of policyString.split(';')) {
                let data = token.trim().split(/ +/);
                if (!data[0]) {
                    continue;
                }

                let directive = data[0].toLowerCase();
                if (directive in policy) {
                    continue;
                }

                policy[directive] = new Set(data.slice(1));
            }
            if (Object.keys(policy).length > 0)
                policies.push(policy);
        }

        // add script-src directive if only default-src is present
        for (const policy of policies) {
            let scriptElementDirective = getScriptElementDirective(policy);
            if (scriptElementDirective === 'default-src') {
                policy['script-src'] = new Set();
                for (const source of policy['default-src']) {
                    policy['script-src'].add(source);
                    // remove 'strict-dynamic' from default-src
                    if (source.match(/^'strict-dynamic'$/i))
                        policy['default-src'].delete(source);
                }
            }
        }

        return policies;
    }

    createRetrofittingNonce() {
        let nonce = generateNonce();
        let allowsAllScripts = true;
        // for each policy, check whether a nonce has to be added and if so add it
        for (const policy of this.policies) {
            let scriptElementDirective = getScriptElementDirective(policy);
            if (scriptElementDirective && !allowsAllInlineScripts(policy[scriptElementDirective])) {
                // remove 'none' from default-src
                for (const source of policy[scriptElementDirective]) {
                    if (source.match(/^'none'$/i))
                        policy[scriptElementDirective].delete(source);
                }
                // add nonce
                policy[scriptElementDirective].add(`'nonce-${nonce}'`);
                allowsAllScripts = false;
            }
        }

        // return no nonce if we did not add it to any policy
        if (allowsAllScripts)
            return null;

        return nonce;
    }

    toString() {
        let cspString = '';
        for (const policy of this.policies) {
            let policyString = '';
            for (const [directive, sources] of Object.entries(policy)) {
                policyString += `${directive} ${Array.from(sources).join(' ')}; `;
            }
            cspString += `${policyString.slice(0, -2)}, `;
        }
        return cspString.slice(0, -2);
    }
}

function getCSP(response, responseText) {
    let serializedPolicies = [];

    // collect all CSPs set via meta-tags
    let matches = responseText.matchAll(/<!--.*?-->|(<meta[^>]+?http-equiv="Content-Security-Policy"[^>]*>)/ig);
    for (const match of matches) {
        if (match && match[1]) {
            let cspMatch = match[1].match(/content="([^"]+)"/i);
            if (cspMatch) {
                let csp = cspMatch[1];

                // remove directives that are illegal within CSPs declared by meta elements
                let illegalDirectiveMatch;
                while (illegalDirectiveMatch = csp.match(/(frame-ancestors|report-uri|sandbox)[^;]*;?/))
                    csp = csp.replace(illegalDirectiveMatch[0], '');

                serializedPolicies.push(csp);
                // remove CSP meta-tag
                responseText = responseText.replace(match[0], '');
            }
        }
    }

    if (response.headers.has('Content-Security-Policy')) {
        serializedPolicies.push(response.headers.get('Content-Security-Policy'));
    }

    if (serializedPolicies.length) {
        return new CSP(serializedPolicies.join(', '));
    }

    return null;
}

async function getProxyResponse(event) {
    // simulate browser's default request handling
    const response = await fetch(event.request); // getResponse ? await getResponse(event) : await fetch(event.request);

    if (response.headers.has('content-type') && response.headers.get('content-type').toLowerCase().includes('text/html')) {
        // read the responseText of a response clone (prevents modifying the server response by resolving the text promise)
        let responseText = await response.clone().text();

        let csp = getCSP(response, responseText);
        if (csp) {
            for (const Retrofitter of RETROFITTERS) {
                responseText = Retrofitter.retrofit(csp, responseText);
            }

            // update Content-Security-Policy header
            const newHeaders = new Headers(response.headers);
            newHeaders.set('Content-Security-Policy', csp.toString());

            return new Response(responseText, {
                status: response.status,
                statusText: response.statusText,
                headers: newHeaders
            });
        }
    }
    // response does not contain a CSP => no retrofitting
    return response;
}

self.addEventListener('fetch', event => event.respondWith(getProxyResponse(event)));

self.addEventListener('install', () => {
    self.skipWaiting();
    console.log('Service Worker has been installed');
});

self.addEventListener('activate', event => {
    event.waitUntil(clients.claim());
    console.log('Service Worker has been activated');
});
