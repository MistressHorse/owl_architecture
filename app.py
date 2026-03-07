from scanner.main import *
from fastapi import FastAPI, Form, Request
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Annotated
from python_multipart import *
from scanner.main import scan as scanner_scan

app = FastAPI()
mode = None
templates = Jinja2Templates(directory='./web/templates')
app.mount('/static', StaticFiles(directory='./web/static'), name='static')

@app.get('/')
def home(request: Request):
    return templates.TemplateResponse('index.html', {'request': request})

@app.post('/scan')
def scan(request: Request,
         direct: Annotated[str, Form()], 
         mode: Annotated[str, Form()]):
    result = scanner_scan(direct, mode)
    return templates.TemplateResponse(
        'results.html',
        {
            'request': request,
            'results': result,
            'count': len(result)
        }
    )
