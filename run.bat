@echo off

start "Client" cmd /k "cd client && npm i && npm run dev"

start "Server" cmd /k "cd server && npm i && npm start"

exit