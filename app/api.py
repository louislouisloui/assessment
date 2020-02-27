import pickle

import matplotlib
from flask import Flask, Blueprint
from flask_restful import Resource, Api

from resources import classify,classify_bulk

matplotlib.use('TkAgg')

api_bp = Blueprint('api', __name__)
api = Api(api_bp)

with open('model/one_class_svm.pickle', 'rb') as handle:
    model_fit = pickle.load(handle)

# Routes
kwargs = {'model_fit': model_fit}
api.add_resource(classify, '/classify', resource_class_kwargs=kwargs)
api.add_resource(classify_bulk, '/classify_bulk', resource_class_kwargs=kwargs)