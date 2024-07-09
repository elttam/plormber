#!/bin/bash

# Very bad lazy way to wait for postgresql
sleep 10;
npx prisma migrate dev --name init;
npx prisma generate;
npm run init && npm run start;