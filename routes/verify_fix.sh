#!/bin/bash
node --import tsx app.ts &
SERVER_PID=$!
echo "Server started with PID $SERVER_PID"
sleep 30
./.exploit/exploit.sh
EXIT_CODE=$?
kill $SERVER_PID
exit $EXIT_CODE
