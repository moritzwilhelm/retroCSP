if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/retroCSP.js', {scope: '/'}).catch(error => console.log('Service Worker registration failed due to', error));
} else if (location.protocol !== 'https:') {
    console.log('Service Workers can only be used if served via https or on localhost');
} else {
    console.log('Service Workers are not supported by your browser');
}
