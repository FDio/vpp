#!/usr/bin/env bash

curl -v -s -o /dev/null --limit-rate $2 --noproxy '*' --max-time $3 -k --http3-only $1 &
curl -v -s -o /dev/null --limit-rate $2 --noproxy '*' --max-time $3 -k --http3-only $1 &
curl -v -s -o /dev/null --limit-rate $2 --noproxy '*' --max-time $3 -k --http3-only $1 &
curl -v -s -o /dev/null --limit-rate $2 --noproxy '*' --max-time $3 -k --http3-only $1 &
curl -v -s -o /dev/null --limit-rate $2 --noproxy '*' --max-time $3 -k --http3-only $1 &
curl -v -s -o /dev/null --limit-rate $2 --noproxy '*' --max-time $3 -k --http3-only $1 &
curl -v -s -o /dev/null --limit-rate $2 --noproxy '*' --max-time $3 -k --http3-only $1 &
curl -v -s -o /dev/null --limit-rate $2 --noproxy '*' --max-time $3 -k --http3-only $1 &
curl -v -s -o /dev/null --limit-rate $2 --noproxy '*' --max-time $3 -k --http3-only $1 &
curl -v -s -o /dev/null --limit-rate $2 --noproxy '*' --max-time $3 -k --http3-only $1 &
curl -v -s -o /dev/null --limit-rate $2 --noproxy '*' --max-time $3 -k --http3-only $1 &
curl -v -s -o /dev/null --limit-rate $2 --noproxy '*' --max-time $3 -k --http3-only $1 &
curl -v -s -o /dev/null --limit-rate $2 --noproxy '*' --max-time $3 -k --http3-only $1 &
curl -v -s -o /dev/null --limit-rate $2 --noproxy '*' --max-time $3 -k --http3-only $1 &
curl -v -s -o /dev/null --limit-rate $2 --noproxy '*' --max-time $3 -k --http3-only $1 &
curl -v -s -o /dev/null --limit-rate $2 --noproxy '*' --max-time $3 -k --http3-only $1 &
curl -v -s -o /dev/null --limit-rate $2 --noproxy '*' --max-time $3 -k --http3-only $1 &
curl -v -s -o /dev/null --limit-rate $2 --noproxy '*' --max-time $3 -k --http3-only $1 &
curl -v -s -o /dev/null --limit-rate $2 --noproxy '*' --max-time $3 -k --http3-only $1 &
curl -v -s -o /dev/null --limit-rate $2 --noproxy '*' --max-time $3 -k --http3-only $1 &
curl -v -s -o /dev/null --limit-rate $2 --noproxy '*' --max-time $3 -k --http3-only $1 &
curl -v -s -o /dev/null --limit-rate $2 --noproxy '*' --max-time $3 -k --http3-only $1 &
curl -v -s -o /dev/null --limit-rate $2 --noproxy '*' --max-time $3 -k --http3-only $1 &
curl -v -s -o /dev/null --limit-rate $2 --noproxy '*' --max-time $3 -k --http3-only $1 &
curl -v -s -o /dev/null --limit-rate $2 --noproxy '*' --max-time $3 -k --http3-only $1 &
curl -v -s -o /dev/null --limit-rate $2 --noproxy '*' --max-time $3 -k --http3-only $1 &
curl -v -s -o /dev/null --limit-rate $2 --noproxy '*' --max-time $3 -k --http3-only $1 &
curl -v -s -o /dev/null --limit-rate $2 --noproxy '*' --max-time $3 -k --http3-only $1 &
curl -v -s -o /dev/null --limit-rate $2 --noproxy '*' --max-time $3 -k --http3-only $1 &
curl -v -s -o /dev/null --limit-rate $2 --noproxy '*' --max-time $3 -k --http3-only $1 &
curl -v -s -o /dev/null --limit-rate $2 --noproxy '*' --max-time $3 -k --http3-only $1 &
curl -v -s -o /dev/null --limit-rate $2 --noproxy '*' --max-time $3 -k --http3-only $1 &
curl -v -s -o /dev/null --limit-rate $2 --noproxy '*' --max-time $3 -k --http3-only $1 &
curl -v -s -o /dev/null --limit-rate $2 --noproxy '*' --max-time $3 -k --http3-only $1 &
curl -v -s -o /dev/null --limit-rate $2 --noproxy '*' --max-time $3 -k --http3-only $1 &
curl -v -s -o /dev/null --limit-rate $2 --noproxy '*' --max-time $3 -k --http3-only $1 &
curl -v -s -o /dev/null --limit-rate $2 --noproxy '*' --max-time $3 -k --http3-only $1 &
curl -v -s -o /dev/null --limit-rate $2 --noproxy '*' --max-time $3 -k --http3-only $1 &
curl -v -s -o /dev/null --limit-rate $2 --noproxy '*' --max-time $3 -k --http3-only $1 &
curl -v -s -o /dev/null --limit-rate $2 --noproxy '*' --max-time $3 -k --http3-only $1 &

failed=0
for pid in $(jobs -p); do
  wait "$pid" || ((failed++))
done

if ((failed > 0)); then
  echo "$failed failed"
  exit 1
fi

echo "all completed successfully"
