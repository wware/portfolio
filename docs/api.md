# APIs and Dynamic Content in MkDocs websites

## Prompt

> I want to add a data API (probably json I guess) next to or inside my MkDocs website, probably using FastAPI. How would that be done? If I do that, can I use React in my Markdown source for dynamic UI stuff?

Let's break down how you can add a data API using FastAPI to your MkDocs website and how you can integrate React for dynamic UI elements within your Markdown content.

**1. Setting up FastAPI alongside MkDocs**

You'll essentially run FastAPI as a separate application, but you'll need to configure it to work alongside your MkDocs site, ideally serving from the same domain or a subdomain.

* **Project Structure:**
    ```
    my-mkdocs-project/
    ├── docs/          # Your Markdown content
    ├── mkdocs.yml    # MkDocs configuration
    ├── api/           # FastAPI application
    │   ├── main.py    # FastAPI routes and logic
    │   └── ...       # Other FastAPI modules
    └── ...
    ```

* **FastAPI Setup (api/main.py):**

    ```python
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel

    app = FastAPI()

    # CORS middleware (important for frontend communication)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Adjust this for production!
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    class Item(BaseModel):
        name: str
        value: int

    @app.get("/api/items")
    async def get_items():
        items = [
            {"name": "Item 1", "value": 10},
            {"name": "Item 2", "value": 20},
        ]
        return items

    @app.post("/api/items")
    async def create_item(item: Item):
        # Process the item (e.g., store it in a database)
        return {"message": "Item created", "item": item}
    ```

* **Running FastAPI:**

    ```bash
    cd api
    uvicorn main:app --reload
    ```

* **Serving MkDocs and FastAPI together:**

    * **Reverse Proxy (Recommended for Production):** Use a web server like Nginx or Apache to reverse proxy requests to your MkDocs build and your FastAPI application.
        * Example Nginx configuration:
            ```nginx
            server {
                listen 80;
                server_name yourdomain.com; #or localhost

                location / {
                    root /path/to/your/mkdocs/site; #the site folder created by mkdocs build.
                    index index.html;
                }

                location /api/ {
                    proxy_pass http://127.0.0.1:8000; #FastAPI port
                    proxy_set_header Host $host;
                    proxy_set_header X-Real-IP $remote_addr;
                    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                    proxy_set_header X-Forwarded-Proto $scheme;
                }
            }
            ```
    * **Development:** For development, you can run both separately and use CORS to allow communication between them.

**2. Integrating React into Markdown with MkDocs**

While you can't directly embed React components into Markdown, you can achieve dynamic UI by:

* **Custom JavaScript:**
    * Add JavaScript to your MkDocs site that fetches data from your FastAPI API.
    * Use this JavaScript to dynamically generate HTML elements and update them with the API data.
    * You can include your javascript inside your `docs/javascripts` folder, and then add it to your `mkdocs.yml` file.
    * Example javascript:
        ```javascript
        fetch('/api/items')
            .then(response => response.json())
            .then(data => {
                const itemsContainer = document.getElementById('items-container');
                if (itemsContainer) {
                    data.forEach(item => {
                        const itemElement = document.createElement('div');
                        itemElement.textContent = `${item.name}: ${item.value}`;
                        itemsContainer.appendChild(itemElement);
                    });
                }
            });
        ```
    * And in your markdown file:
        ```markdown
        # Dynamic Items

        <div id="items-container"></div>
        ```

* **Embedding React Build:**
    * Build your React application as a static bundle.
    * Place the build output (HTML, CSS, JavaScript) in your `docs/` directory or a subdirectory.
    * Link to the React application from your Markdown content using `<iframe>` or by creating links.
    * For complex applications, this is often the best approach.
    * You can serve the react build using the same webserver that serves the mkdocs files.
* **MkDocs Plugins:**
    * Explore MkDocs plugins that might offer better integration with JavaScript or allow for custom HTML injection.
    * There are not many plugins that will allow direct react injection, so the javascript or the build injection methods are the most common.

**Important Considerations:**

* **CORS:** Ensure your FastAPI application has appropriate CORS settings to allow requests from your MkDocs domain.
* **Security:** If your API handles sensitive data, implement proper authentication and authorization.
* **Deployment:** Consider how you'll deploy both your MkDocs site and your FastAPI application. Docker and container orchestration tools can simplify this process.
* **Performance:** Optimize your FastAPI API for performance, especially if it handles a large volume of requests.
* **React Integration:** If you are using React, consider how you will manage routing, state, and component communication when embedding it into your MkDocs site.

By combining FastAPI for your data API and careful JavaScript or React integration, you can create a dynamic and interactive MkDocs website.

## More about FastAPI and MkDocs Integration

### Prompt
How to run `mkdocs serve` and FastAPI process together on the same port?

#### Solution Implemented
1. Modify FastAPI app to serve MkDocs content using StaticFiles
2. Key code changes:
   ```python
   app.mount("/", StaticFiles(directory="site", html=True), name="site")
   ```

#### Implementation Steps
1. Build MkDocs site:
   ```bash
   mkdocs build
   ```
2. Configure mkdocs.yml:
   ```yaml
   site_url: http://localhost:8000/
   ```
3. Run FastAPI application:
   ```bash
   uvicorn api.main:app --reload
   ```

#### Result
- API endpoints available at `/api/...`
- Documentation served at root URL `/`
- Single server handling both services

## Notes
- Remember to rebuild MkDocs when documentation changes
- Consider using file watcher or supervisor for development
- Production might benefit from reverse proxy setup