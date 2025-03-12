# Items Demo

We can run MkDocs and FastAPI together, allowing us to have
a static site that can also have dynamic content. Here are
some FastAPI routes:

```python
--8<-- "api/main.py:22:34"
```

And here is where we use it.

```html
--8<-- "docs/example.md:24:42"
```

```javascript
--8<-- "docs/javascripts/extra.js"
```

Here's a demo of a list of items that we fetch from the FastAPI
backend, and also add an item to the list.

<div id="items-container"></div>
<button onclick="do_fetch()"
        style="background-color: #4CAF50; border: 2px solid #45a049; padding: 10px 20px; color: white; cursor: pointer; border-radius: 4px;"
    >Refresh list of items</button>
<button onclick="addItem3()"
        style="background-color: #ff9800; border: 2px solid #f57c00; padding: 10px 20px; color: white; cursor: pointer; border-radius: 4px;"
    >Add another item</button>

<script src="/javascripts/extra.js"></script>
<script>
function addItem3() {
    fetch('/api/items', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: "Item 3", value: 30 })
    })
    .then(() => do_fetch());  // Refresh the list after adding
}
</script>
