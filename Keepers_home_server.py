from app import create_app
import os

app = create_app()

if __name__ == "__main__":
    port = os.environ.get('PORT')
    if port:
        app.run(host='0.0.0.0', port=int(port))
    else:
        app.run(debug=True)