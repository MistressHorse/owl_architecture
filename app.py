from main import *
from fastapi import FastAPI, Form, Request
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from typing import Annotated
from python_multipart import *


app = FastAPI()
mode = None
templates = Jinja2Templates(directory='./web/templates')
app.mount('/static', StaticFiles(directory='./web/static'), name='static')

@app.get('/')
async def home(request: Request):
    return templates.TemplateResponse(name='index.html', context={'request': request})

@app.post('/scan')
def scan(request: Request,
         direct: Annotated[str, Form()], 
         mode: Annotated[str, Form()]):
    
    scan_project(direct, mode)
    with open(f'./audit_json/{mode}_audit_result.json', 'r', encoding='utf-8') as f:
        result = json.load(f)

    return templates.TemplateResponse(
        name='tablet.html',
        context={
            'request': request,
            'results': result,
            'count': len(result)
        }
    )