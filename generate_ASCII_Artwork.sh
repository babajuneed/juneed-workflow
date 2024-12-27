# Build a message by invoking ADVICESLIP API

Curl -s https://api.adviceslip.com/advice > advice.json
cat advice.json

# Test to make sure the advice message has more than 5 words.
cat advice.json | jq -r .slip.advice > advice.message
