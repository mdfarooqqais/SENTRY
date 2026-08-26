```javascript
document.addEventListener("DOMContentLoaded", function () {

    updateClock();

    setInterval(updateClock, 1000);

});


function updateClock() {

    const clock = document.getElementById("currentTime");

    if (!clock) {
        return;
    }

    const now = new Date();

    const hours = String(now.getHours()).padStart(2, "0");
    const minutes = String(now.getMinutes()).padStart(2, "0");
    const seconds = String(now.getSeconds()).padStart(2, "0");

    clock.textContent = `${hours}:${minutes}:${seconds}`;
}
```
