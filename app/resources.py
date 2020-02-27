import re
import pickle
import json
from collections import namedtuple
from functools import reduce

import pandas as pd
import numpy as np
import pyparsing as pp
from flask_restful import Resource, request

def parseAction(string, location, tokens):
    return node(tokens.product,tokens.product_version,tokens.comments, tokens.cousins)

def parse_user_ag(x):
    nodes = grammar.parseString(x)[0]
    comment_pattern = re.compile('^(?P<product>.*?)(?P<comment> \(?.*?\))?$')
    result = list()
    current_node = nodes
    while True:
        product_name = current_node.product
        if len(current_node.comments) > 0:
            for comment in current_node.comments:
                match = re.match(comment_pattern, comment)
                result.append((product_name,match.group('product'),match.group('comment')))
        else:
            result.append((product_name,'not_available','not_available'))
        if current_node.cousins == '':
            break
        else: 
            current_node = current_node.cousins[0]
    return result

def map_tuple(x, mapping, tup):
    not_av = 0
    return mapping.get((x[tup[0]],x[tup[1]]),not_av)

def map_tuple3(x, mapping, tup):
    not_av = -1
    return mapping.get((x[tup[0]],x[tup[1]],x[tup[2]]),not_av)

def unique_count(x):
    uniques = list(x.unique())
    return len(uniques) if 'not_available' not in uniques else len(uniques)-1

# Parser for the main products
LPAR,RPAR,SLASH = map(pp.Suppress, "()/")
product = pp.Word(pp.printables).setResultsName('product')
product_version = SLASH+pp.Word(pp.printables)
value = (pp.quotedString 
         | pp.originalTextFor(pp.OneOrMore(pp.Word(pp.printables, excludeChars="();") 
                                     | pp.nestedExpr())))
comments = LPAR + pp.delimitedList(value,delim=";") + RPAR
grammar = pp.Forward()
grammar << product + pp.Optional(product_version).setResultsName('product_version') \
        + pp.Optional(comments).setResultsName('comments') \
        + pp.ZeroOrMore(grammar).setResultsName('cousins')
node = namedtuple("Node", ["product", "product_version", "comments","cousins"])
grammar.setParseAction(parseAction)

with open('./model/products_lvl_0_dict.pickle','rb') as a:
    products_lvl_0_dict = pickle.load(a)
with open('./model/products_lvl_1_dict.pickle','rb') as b:
    products_lvl_1_dict = pickle.load(b)
with open('./model/comments_lvl_0_dict.pickle','rb') as c:
    comments_lvl_0_dict = pickle.load(c)
with open('./model/comments_lvl_1_dict.pickle','rb') as d:
    comments_lvl_1_dict = pickle.load(d)
with open('./model/comments_lvl_0_dict_rel_2_product.pickle','rb') as e:
    comments_lvl_0_dict_rel_2_product = pickle.load(e)
with open('./model/comments_lvl_1_dict_rel_2_product.pickle','rb') as e:
    comments_lvl_1_dict_rel_2_product = pickle.load(e)

class classify(Resource):
    pred_map = {1:'benign',-1:'exploit'}
    def __init__(self, **kwargs):
        self.model = kwargs['model_fit']
    
    def post(self):
        req = request.get_json()
        prediction = self.model.predict(self.format_user_agent(req.get('raw_user_agent')))
        return {'prediction':self.pred_map.get(prediction[0])}

    def format_user_agent(self, user_agent):
        # Extract the user agent
        user_ag_valid = pd.Series(user_agent).str.strip().str.contains('^\w.*')
        user_ag_parsed = pd.Series(user_agent).loc[user_ag_valid].apply(lambda x: parse_user_ag(x))
        user_ag_parsed = pd.Series( [[('not_available','not_available','not_available')]] * np.invert(user_ag_valid).sum()).append(user_ag_parsed,ignore_index = True)

        user_ag_parsed_unpivot = user_ag_parsed.apply(pd.Series).fillna({0:'-'})\
                            .reset_index().melt(id_vars = 'index').drop(columns = ['variable'])\
                            .dropna().rename(columns={'index':'id'})

        user_ag_parsed_unpivot_exploded = pd.DataFrame(user_ag_parsed_unpivot.value.tolist()\
                                                    ,columns = ['products','comments','comment_details']\
                                                    , index = user_ag_parsed_unpivot.id).fillna('not_available')
        user_ag_parsed_unpivot_exploded.products = user_ag_parsed_unpivot_exploded.products.where(user_ag_parsed_unpivot_exploded.products != '-','not_available')

        #clean
        for col in user_ag_parsed_unpivot_exploded.columns:
            user_ag_parsed_unpivot_exploded.loc[:,col] = user_ag_parsed_unpivot_exploded.loc[:,col].str.lower().str.strip()

        product_pat = re.compile('^(?P<products_main>\w*[a-z])\/?(?P<product_versions>.*)')
        user_ag_parsed_unpivot_exploded = pd.concat([user_ag_parsed_unpivot_exploded,user_ag_parsed_unpivot_exploded.products.str.extract(product_pat)],axis = 1).fillna('not_available')
        user_ag_parsed_unpivot_exploded['product_lvl_0'] = user_ag_parsed_unpivot_exploded.products_main.map(products_lvl_0_dict).fillna(0)
        user_ag_parsed_unpivot_exploded['product_lvl_1'] = user_ag_parsed_unpivot_exploded.loc[:,['products_main','product_versions']].apply(lambda x: map_tuple(x,products_lvl_1_dict,('products_main','product_versions')),axis = 1)

        # Nokias
        nokia = re.compile('(?P<comment_main>series.*?) (?P<comment_version>nokia.*)')
        # WIndows
        windows = re.compile('(?P<comment_main>windows \w{2}) (?P<comment_version>.*)')
        # v/rv
        rv = re.compile('(?P<comment_main>\w*v):(?P<comment_version>.*)')
        # Mac
        mac = re.compile('^cpu (?P<comment_main>.*) (?P<comment_version>(\d_)+\d)+ like mac.*')
        # Else
        fall_back = re.compile('^(?P<comment_main>\w*[a-z])\/?(?P<comment_version>.*)')

        # Extract
        pats = [nokia, windows, rv, mac, fall_back]
        pat_extracted = [user_ag_parsed_unpivot_exploded.comments.str.lower().str.extract(pat).loc[:,['comment_main','comment_version']] for pat in pats]

        # Reduce
        comment_main = reduce(lambda x,y: x.combine_first(y),[i.comment_main for i in pat_extracted])
        comment_version = reduce(lambda x,y: x.combine_first(y),[i.comment_version for i in pat_extracted])

        # Merge
        comments_detailed = pd.concat([user_ag_parsed_unpivot_exploded,comment_main,comment_version], axis = 1)

        #Clean
        comments_detailed.comment_version = comments_detailed.comment_version.where(comments_detailed.comment_version!='','not_available') 

        comments_detailed['comment_lvl_0'] = comments_detailed.comment_main.map(comments_lvl_0_dict).fillna(0)
        comments_detailed['comment_lvl_1'] = comments_detailed.loc[:,['comment_main','comment_version']].apply(lambda x: map_tuple(x,comments_lvl_1_dict,('comment_main','comment_version')),axis = 1)
        
        comments_detailed['comment_lvl_0_rel_2_product'] = comments_detailed.loc[:,['products','comment_main']].apply(lambda x: map_tuple(x,comments_lvl_0_dict_rel_2_product,('products','comment_main')),axis = 1)
        comments_detailed['comment_lvl_1_rel_2_product'] = comments_detailed.loc[:,['products','comment_main','comment_version']].apply(lambda x: map_tuple3(x,comments_lvl_1_dict_rel_2_product,('products','comment_main','comment_version')),axis = 1)
        
        # Agg
        desc_stat = ['mean','max','min']
        apply_map = {'comment_lvl_1':desc_stat,
                    'comment_lvl_1_rel_2_product':desc_stat}
        comment_detail_summary = comments_detailed.groupby(level = 0)[list(apply_map.keys())].agg(desc_stat)
        comment_detail_summary.columns = ['_'.join(col) for col in comment_detail_summary.columns]

        # product main count
        product_main_count = comments_detailed.groupby(level=0)['products_main'].apply(lambda x: unique_count(x)).to_frame()
        product_main_count.columns = ['products_main_count']
        #Product main stats
        product_main_lvl_0_summary = comments_detailed.reset_index().drop_duplicates(['id','products_main']).groupby('id')['product_lvl_0'].agg(desc_stat)
        product_main_lvl_0_summary.columns = ['product_main_lvl_0_'+col for col in product_main_lvl_0_summary.columns]
        # Product version stats
        product_main_lvl_1_summary = comments_detailed.reset_index().drop_duplicates(['id','products_main','product_versions']).groupby('id')['product_lvl_1'].agg(desc_stat)
        product_main_lvl_1_summary.columns = ['product_main_lvl_1_'+col for col in product_main_lvl_1_summary.columns]
        product_main_lvl_1_summary
        #Product version count stats
        product_version_count = comments_detailed.reset_index().groupby(['id','products_main'])['product_versions'].apply(lambda x: unique_count(x))
        product_version_count_stats = product_version_count.to_frame().reset_index(level = 1,drop=True).groupby(level = 0).agg(desc_stat)
        product_version_count_stats.columns = ['_count_'.join(col) for col in product_version_count_stats.columns]
        # Comment main stats
        comment_main_summary = comments_detailed.reset_index().drop_duplicates(['id','products','comment_main']).groupby('id')[['comment_lvl_0','comment_lvl_0_rel_2_product']].agg(desc_stat)
        comment_main_summary.columns = ['_'.join(col) for col in comment_main_summary.columns]
        # Comment main counts
        comment_main_count = comments_detailed.reset_index().drop_duplicates(['id','products','comment_main']).groupby(['id','products'])['comment_main'].apply(lambda x: unique_count(x))
        comment_main_count_summary = comment_main_count.reset_index('products',drop=True).groupby(level = 0).agg(desc_stat)
        comment_main_count_summary.columns = ['comment_main_count_'+col for col in comment_main_count_summary.columns]
        dt_agg = pd.concat([comment_detail_summary,\
                        comment_main_count_summary,\
                        comment_main_summary,\
                        product_version_count_stats,\
                        product_main_lvl_1_summary,\
                        product_main_count,\
                        product_main_lvl_0_summary], axis = 1)
        return dt_agg.values

class classify_bulk(Resource):
    pred_map = {1:'benign',-1:'exploit'}
    def __init__(self, **kwargs):
        self.model = kwargs['model_fit']
    
    def post(self):
        req = request.get_json()
        X = self.format_user_agent(req)
        prediction = pd.DataFrame(self.model.predict(X.values),index = X.index,columns = ['predicted_class'])
        prediction.predicted_class = prediction.predicted_class.map(self.pred_map)
        return prediction.to_dict()

    def format_user_agent(self, user_agent):
        # Extract the user agent
        user_ag_valid = pd.Series(user_agent).str.strip().str.contains('^\w.*')
        user_ag_parsed = pd.Series(user_agent).loc[user_ag_valid].apply(lambda x: parse_user_ag(x))
        invalid_index = np.invert(user_ag_valid)
        user_ag_parsed = pd.Series( [[('not_available','not_available','not_available')]] * invalid_index.sum(),index = pd.Series(user_agent).loc[invalid_index].index).append(user_ag_parsed)

        user_ag_parsed_unpivot = user_ag_parsed.apply(pd.Series).fillna({0:'-'})\
                            .reset_index().melt(id_vars = 'index').drop(columns = ['variable'])\
                            .dropna().rename(columns={'index':'id'})

        user_ag_parsed_unpivot_exploded = pd.DataFrame(user_ag_parsed_unpivot.value.tolist()\
                                                    ,columns = ['products','comments','comment_details']\
                                                    , index = user_ag_parsed_unpivot.id).fillna('not_available')
        user_ag_parsed_unpivot_exploded.products = user_ag_parsed_unpivot_exploded.products.where(user_ag_parsed_unpivot_exploded.products != '-','not_available')

        #clean
        for col in user_ag_parsed_unpivot_exploded.columns:
            user_ag_parsed_unpivot_exploded.loc[:,col] = user_ag_parsed_unpivot_exploded.loc[:,col].str.lower().str.strip()

        product_pat = re.compile('^(?P<products_main>\w*[a-z])\/?(?P<product_versions>.*)')
        user_ag_parsed_unpivot_exploded = pd.concat([user_ag_parsed_unpivot_exploded,user_ag_parsed_unpivot_exploded.products.str.extract(product_pat)],axis = 1).fillna('not_available')
        user_ag_parsed_unpivot_exploded['product_lvl_0'] = user_ag_parsed_unpivot_exploded.products_main.map(products_lvl_0_dict).fillna(0)
        user_ag_parsed_unpivot_exploded['product_lvl_1'] = user_ag_parsed_unpivot_exploded.loc[:,['products_main','product_versions']].apply(lambda x: map_tuple(x,products_lvl_1_dict,('products_main','product_versions')),axis = 1)

        # Nokias
        nokia = re.compile('(?P<comment_main>series.*?) (?P<comment_version>nokia.*)')
        # WIndows
        windows = re.compile('(?P<comment_main>windows \w{2}) (?P<comment_version>.*)')
        # v/rv
        rv = re.compile('(?P<comment_main>\w*v):(?P<comment_version>.*)')
        # Mac
        mac = re.compile('^cpu (?P<comment_main>.*) (?P<comment_version>(\d_)+\d)+ like mac.*')
        # Else
        fall_back = re.compile('^(?P<comment_main>\w*[a-z])\/?(?P<comment_version>.*)')

        # Extract
        pats = [nokia, windows, rv, mac, fall_back]
        pat_extracted = [user_ag_parsed_unpivot_exploded.comments.str.lower().str.extract(pat).loc[:,['comment_main','comment_version']] for pat in pats]

        # Reduce
        comment_main = reduce(lambda x,y: x.combine_first(y),[i.comment_main for i in pat_extracted])
        comment_version = reduce(lambda x,y: x.combine_first(y),[i.comment_version for i in pat_extracted])

        # Merge
        comments_detailed = pd.concat([user_ag_parsed_unpivot_exploded,comment_main,comment_version], axis = 1)

        #Clean
        comments_detailed.comment_version = comments_detailed.comment_version.where(comments_detailed.comment_version!='','not_available') 

        comments_detailed['comment_lvl_0'] = comments_detailed.comment_main.map(comments_lvl_0_dict).fillna(0)
        comments_detailed['comment_lvl_1'] = comments_detailed.loc[:,['comment_main','comment_version']].apply(lambda x: map_tuple(x,comments_lvl_1_dict,('comment_main','comment_version')),axis = 1)
        
        comments_detailed['comment_lvl_0_rel_2_product'] = comments_detailed.loc[:,['products','comment_main']].apply(lambda x: map_tuple(x,comments_lvl_0_dict_rel_2_product,('products','comment_main')),axis = 1)
        comments_detailed['comment_lvl_1_rel_2_product'] = comments_detailed.loc[:,['products','comment_main','comment_version']].apply(lambda x: map_tuple3(x,comments_lvl_1_dict_rel_2_product,('products','comment_main','comment_version')),axis = 1)
        
        # Agg
        desc_stat = ['mean','max','min']
        apply_map = {'comment_lvl_1':desc_stat,
                    'comment_lvl_1_rel_2_product':desc_stat}
        comment_detail_summary = comments_detailed.groupby(level = 0)[list(apply_map.keys())].agg(desc_stat)
        comment_detail_summary.columns = ['_'.join(col) for col in comment_detail_summary.columns]

        # product main count
        product_main_count = comments_detailed.groupby(level=0)['products_main'].apply(lambda x: unique_count(x)).to_frame()
        product_main_count.columns = ['products_main_count']
        #Product main stats
        product_main_lvl_0_summary = comments_detailed.reset_index().drop_duplicates(['id','products_main']).groupby('id')['product_lvl_0'].agg(desc_stat)
        product_main_lvl_0_summary.columns = ['product_main_lvl_0_'+col for col in product_main_lvl_0_summary.columns]
        # Product version stats
        product_main_lvl_1_summary = comments_detailed.reset_index().drop_duplicates(['id','products_main','product_versions']).groupby('id')['product_lvl_1'].agg(desc_stat)
        product_main_lvl_1_summary.columns = ['product_main_lvl_1_'+col for col in product_main_lvl_1_summary.columns]
        product_main_lvl_1_summary
        #Product version count stats
        product_version_count = comments_detailed.reset_index().groupby(['id','products_main'])['product_versions'].apply(lambda x: unique_count(x))
        product_version_count_stats = product_version_count.to_frame().reset_index(level = 1,drop=True).groupby(level = 0).agg(desc_stat)
        product_version_count_stats.columns = ['_count_'.join(col) for col in product_version_count_stats.columns]
        # Comment main stats
        comment_main_summary = comments_detailed.reset_index().drop_duplicates(['id','products','comment_main']).groupby('id')[['comment_lvl_0','comment_lvl_0_rel_2_product']].agg(desc_stat)
        comment_main_summary.columns = ['_'.join(col) for col in comment_main_summary.columns]
        # Comment main counts
        comment_main_count = comments_detailed.reset_index().drop_duplicates(['id','products','comment_main']).groupby(['id','products'])['comment_main'].apply(lambda x: unique_count(x))
        comment_main_count_summary = comment_main_count.reset_index('products',drop=True).groupby(level = 0).agg(desc_stat)
        comment_main_count_summary.columns = ['comment_main_count_'+col for col in comment_main_count_summary.columns]
        dt_agg = pd.concat([comment_detail_summary,\
                        comment_main_count_summary,\
                        comment_main_summary,\
                        product_version_count_stats,\
                        product_main_lvl_1_summary,\
                        product_main_count,\
                        product_main_lvl_0_summary], axis = 1)
        return dt_agg