#!/usr/bin/env bash

docker build -t secure-sending-system .

ENV_FILE="./server/.env"
DB_FILE="./server/database.db"

if [ ! -f $ENV_FILE ]; then
  echo "No .env file found. Go to ./server.env and fill your credentials before starting!"
  cp ./server/.env.example ./server/.env
  exit 1
fi

if ! grep -qE "^JWT_SECRET=\"[a-zA-Z0-9+/]{32,}={0,2}\"$" "$ENV_FILE"; then
  echo "Invalid or missing JWT_SECRET in .env"
  exit 1
fi

if ! grep -qE "^MASTER_KEY=\"[a-zA-Z0-9+/]{32,}={0,2}\"$" "$ENV_FILE"; then
  echo "Invalid or missing MASTER_KEY in .env"
  exit 1
fi

if [ ! -f "$DB_FILE" ]; then
  touch "$DB_FILE"
fi

docker run -p 5000:5000 \
  -v $(pwd)/server/database.db:/app/server/database.db \
  -v $(pwd)/server/.env:/app/server/.env \
  secure-sending-system