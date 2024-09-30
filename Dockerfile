# Use the official Python 3.11 image as the base image
# Consider using a full image if you encounter issues with missing libraries
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container at /app
COPY requirements.txt .

# Install any dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application's code into the container at /app
COPY . .

# Set up environment variables from .env file based on app env
# This assumes .env is at the root of the project
COPY .env /app/.env

# Copy run script and allow it to run
COPY run.sh /app/run.sh
RUN chmod +x /app/run.sh

# Specify the commands to run the application, it runs a sh script to run several commands
CMD ["/app/run.sh"]
