async function register_service_worker(scriptURL) {
    try {
        let registration = await navigator.serviceWorker.register(scriptURL, {scope: '/'});

        // updatefound fires if registration.installing acquires a new SW => a new SW is currently being installed
        registration.addEventListener('updatefound', () => {
            // statechange at registration.installing means that this new SW has finished installation/activation
            registration.installing.addEventListener('statechange', event => {
                if (event.target.state === 'activated') {
                    console.log('RELOADING');
                    location.reload();
                }
            });
        });
    } catch (error) {
        console.log('Service Worker registration failed due to', error);
    }
}

if ('serviceWorker' in navigator) {
    register_service_worker('/retroCSP.js');
} else if (location.protocol !== 'https:') {
    console.log('Service Workers can only be used if served via https or on localhost');
} else {
    console.log('Service Workers are not supported by your browser');
}
