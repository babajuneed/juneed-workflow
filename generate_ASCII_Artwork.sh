# Build a message by invoking ADVICESLIP API

Curl -s https://api.adviceslip.com/advice > advice.json
cat advice.json

# Test to make sure the advice message has more than 5 words.
cat advice.json | jq -r .slip.advice > advice.message
[ $(wc -w < advice.message) -gt 5 ] && echo "Advice has more than 5 words" || (echo "Advice - $(cat advice.message) has 5 words")

# Deploy
sudo apt-get install cowsay -y
cat advice.message | cowsay -f $(ls /usr/share/cowsay/cows | shuf -n 1)