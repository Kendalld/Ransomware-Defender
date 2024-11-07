FROM python:3
WORKDIR /usr/src/app
ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0  
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
EXPOSE 5001
COPY . .
CMD ["python", "./app.py"]