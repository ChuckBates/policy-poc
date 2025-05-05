FROM scratch

# Bundle must have a /policy/.manifest or /policy/data.json + .rego files
COPY policies /policy