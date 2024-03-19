import fastapi
from fastapi import Request, HTTPException, Response
from fastapi.responses import JSONResponse, StreamingResponse
import httpx
import asyncio
import csv
import datetime
import argparse
import json

# Step 1: Setup argparse
parser = argparse.ArgumentParser(description="Run a proxy server with authentication and logging.")
parser.add_argument("--log-file", default="access_log.csv", help="Path to the access log file.")
parser.add_argument("--port", type=int, default=9600, help="Port number for the server.")
parser.add_argument("--api-keys-file", default="api_keys.txt", help="Path to the authorized users list.")
args = parser.parse_args()

app = fastapi.FastAPI()

# Step 2: Load API Keys
def load_api_keys(filename):
    with open(filename, "r") as file:
        keys = file.read().splitlines()
    return {key.split(":")[0]: key.split(":")[1] for key in keys}

api_keys = load_api_keys(args.api_keys_file)

# Logging function
async def log_request(username, ip_address, event, access):
    with open(args.log_file, "a", newline='') as csvfile:
        log_writer = csv.writer(csvfile)
        log_writer.writerow([datetime.datetime.now(), event, username, ip_address, access])

# Step 3: Authentication Middleware
@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    print(f"auth_middleware {datetime.datetime.now()}")
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        token_parts = token.split(":")
        if len(token_parts) != 2:
            await log_request("unknown", request.client.host, "gen_request", "Denied")
            raise HTTPException(status_code=401, detail="Invalid key format. Expected username:secret.")
        username, secret = token_parts
        if username in api_keys and api_keys[username] == secret:
            response = await call_next(request)
            await log_request(username, request.client.host, "gen_request", "Authorized")
            return response
        else:
            await log_request(username, request.client.host, "gen_request", "Denied")
            raise HTTPException(status_code=401, detail="Invalid key")
    await log_request("unknown", request.client.host, "gen_request", "Denied")
    raise HTTPException(status_code=401, detail="Unauthorized")

# Step 4: Forward Requests
async def forward_request(path: str, method: str, headers: dict, body=None):
    #print(f"forward_request {datetime.datetime.now()}")
    url = f"http://localhost:8000{path}"
    async with httpx.AsyncClient(http2=True, limits=httpx.Limits(max_connections=100, max_keepalive_connections=20)) as client:
        #print(f"the with started {datetime.datetime.now()}")
        if method == "GET":
            response = await client.get(url, headers=headers)
        elif method == "POST":
            response = await client.post(url, headers=headers, json=body)
        #print(f"response ok {datetime.datetime.now()}")
            
        # Handle streaming mode
        if "stream" in path:
            async def stream_response():
                async for chunk in response.aiter_bytes():
                    yield chunk
            return StreamingResponse(stream_response(), media_type="text/event-stream")
        return response

@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE"], include_in_schema=False)
async def proxy(request: Request, full_path: str):
    # print(f"proxy {datetime.datetime.now()}")
    method = request.method
    headers = dict(request.headers)
    body = await request.json() if method == "POST" and request.headers.get("Content-Type", "") == "application/json" else None
    response = await forward_request(f"/{full_path}", method, headers, body)
    if isinstance(response, StreamingResponse):
        return response
    try:
        # Attempt to parse the response as JSON only if the content is not empty
        if response.content:
            return JSONResponse(content=response.json(), status_code=response.status_code)
        else:
            # If the response is empty, return a generic response or handle accordingly
            return Response(content='', status_code=response.status_code, media_type="text/plain")
    except json.decoder.JSONDecodeError:
        # If the response cannot be parsed as JSON, return the raw response or handle accordingly
        return Response(content=response.text, status_code=response.status_code, media_type="text/plain")

# Step 7: Run the Proxy Server
import uvicorn
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=args.port)
