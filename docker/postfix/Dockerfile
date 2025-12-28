FROM tozd/postfix:ubuntu-jammy

#Todo: as soon as it works copy scripts into the images instead of mapping them

# Update package lists and install Python3 pip and build dependencies
RUN apt-get update && apt-get install -y python3-pip && \
    pip3 install --no-cache-dir mysql-connector-python python-dotenv && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# The default CMD/ENTRYPOINT from base image stays, so postfix runs as usual
