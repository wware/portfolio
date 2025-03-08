# Will Ware's portfolio website

I want to set up a portfolio website for my software engineering skills and interests.

The portfolio should feel like you're stepping thru a science museum with wonders around
every corner.

It would be cool to have a local GitHub clone with pages and actions for CI/CD pipelines
and documentation.

Pages will be organized and rendered with MkDocs/Material/Mermaid, and eventually pushed to
`wware.github.io` when ready.

Borrow ideas from `eslam-abdo.github.io`. He did a nice job with some lovely effects.

## MkDocs Commands

For full documentation visit [mkdocs.org](https://www.mkdocs.org).

* `mkdocs new [dir-name]` - Create a new project.
* `mkdocs serve` - Start the live-reloading docs server.
* `mkdocs serve -a '0.0.0.0:8000'` if you want it available elsewhere on the LAN.
* `mkdocs build` - Build the documentation site.
* `mkdocs -h` - Print help message and exit.

### Mkdocs-Material docker container

To make this work, I need to make a `Dockerfile` that does
`pip install mkdocs-mermaid2-plugin` before building the docs and
running the server.

```bash
docker run --rm -it -p 8000:8000 -v $(pwd):/docs squidfunk/mkdocs-material
```

