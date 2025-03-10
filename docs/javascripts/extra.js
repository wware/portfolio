function do_fetch() {
    return fetch('/api/items')
        .then(response => response.json())
        .then(data => {
            console.log(data);
            const itemsContainer = document.getElementById('items-container');
            itemsContainer.innerHTML = '';
            if (itemsContainer) {
                data.forEach(item => {
                    const itemElement = document.createElement('div');
                    itemElement.textContent = `${item.name}: ${item.value}`;
                    itemsContainer.appendChild(itemElement);
                });
            }
        });
}
