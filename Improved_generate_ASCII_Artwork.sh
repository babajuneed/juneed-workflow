#!/bin/bash

# Set API endpoint and output file names
API_ENDPOINT="(link unavailable)"  # URL of the API endpoint to fetch advice
ADVICE_JSON="advice.json"  # Output file name for the JSON response
ADVICE_MESSAGE="advice.message"  # Output file name for the extracted advice message

# Fetch advice from API
fetch_advice() {
  # Use curl to send a silent (-s) and fail-on-error (-f) request to the API endpoint
  curl -s -f "$API_ENDPOINT" -o "$ADVICE_JSON"
  
  # Check if the curl command was successful (exit status 0)
  if [ $? -ne 0 ]; then
    # If not, print an error message and exit the script with status 1
    echo "Failed to fetch advice from API"
    exit 1
  fi
}

# Extract advice message from JSON
extract_advice() {
  # Use jq to extract the advice message from the JSON response
  # The -r option tells jq to output the result as a raw string
  jq -r '.slip.advice' "$ADVICE_JSON" > "$ADVICE_MESSAGE"
  
  # Check if the jq command was successful (exit status 0)
  if [ $? -ne 0 ]; then
    # If not, print an error message and exit the script with status 1
    echo "Failed to extract advice message from JSON"
    exit 1
  fi
}

# Check if advice message has more than 5 words
check_advice_length() {
  # Use wc to count the number of words in the advice message
  word_count=$(wc -w < "$ADVICE_MESSAGE")
  
  # Check if the word count is greater than 5
  if [ $word_count -gt 5 ]; then
    # If so, print a message indicating that the advice has more than 5 words
    echo "Advice has more than 5 words"
  else
    # Otherwise, print a message indicating that the advice has 5 words or less
    echo "Advice - $(cat "$ADVICE_MESSAGE") has 5 words or less"
  fi
}

# Deploy advice message using cowsay
deploy_advice() {
  # Check if the cowsay command is available
  if ! command -v cowsay &> /dev/null; then
    # If not, print a message indicating that cowsay will be installed
    echo "Installing cowsay package..."
    # Install cowsay using apt-get
    sudo apt-get install -y cowsay
  fi
  
  # Pipe the advice message to cowsay, using a random cow theme
  cat "$ADVICE_MESSAGE" | cowsay -f $(ls /usr/share/cowsay/cows | shuf -n 1)
}

# Main script
# Call each function in sequence to fetch, extract, check, and deploy the advice
fetch_advice
extract_advice
check_advice_length
deploy_advice