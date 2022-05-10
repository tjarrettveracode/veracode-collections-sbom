from gc import collect
import sys
import argparse
import logging
import datetime
import json
from uuid import UUID

import anticrlf
from requests import RequestException

from veracode_api_py import VeracodeAPI as vapi, Collections, SBOM

log = logging.getLogger(__name__)

def setup_logger():
    handler = logging.FileHandler('vccollections-sbom.log', encoding='utf8')
    handler.setFormatter(anticrlf.LogFormatter('%(asctime)s - %(levelname)s - %(funcName)s - %(message)s'))
    logger = logging.getLogger(__name__)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

def creds_expire_days_warning():
    creds = vapi().get_creds()
    exp = datetime.datetime.strptime(creds['expiration_ts'], "%Y-%m-%dT%H:%M:%S.%f%z")
    delta = exp - datetime.datetime.now().astimezone() #we get a datetime with timezone...
    if (delta.days < 7):
        print('These API credentials expire ', creds['expiration_ts'])

def is_valid_uuid(uuid_to_test, version=4):
    try:
        uuid_obj = UUID(uuid_to_test, version=version)
    except ValueError:
        return False
    return str(uuid_obj) == uuid_to_test

def prompt_for_collection(prompt_text):
    collguid = ""
    collection_name_search = input(prompt_text)
    collection_candidates = Collections().get_by_name(collection_name_search)
    if len(collection_candidates) == 0:
        print("No matches were found!")
    elif len(collection_candidates) > 1:
        print("Please choose a collection:")
        for idx, collection in enumerate(collection_candidates,start=1):
            print("{}) {}".format(idx, collection["name"]))
        i = input("Enter number: ")
        try:
            if 0 < int(i) <= len(collection_candidates):
                collguid = collection_candidates[int(i)-1].get('guid')
                print('Selected collection {}'.format(collection_candidates[int(i)-1]['name']))
        except ValueError:
            collguid = ""
    else:
        collguid = collection_candidates[0].get('guid')
        print('Selected collection {}'.format(collection_candidates[0]['name']))

    return collguid

def get_collection(collguid):
    return Collections().get(collguid)

def get_collection_assets(collguid):
    return Collections().get_assets(collguid)

def get_sboms(assets):
    #TODO add a try around the get and handle the 401 exception when no sbom exists
    sboms = []
    for asset in assets:
        this_app = asset['asset_info']['guid']
        try:
            sboms.append(SBOM().get(this_app))
        except RequestException:
            status = 'Could not get SBOM for application {}'.format(this_app)
            print(status)
            log.info(status)

    return sboms

def make_collection_sbom_metadata(sboms, collection):
    mtdt = {}
    mtdt['timestamp'] = collection['modified']
    mtdt['authors'] = sboms[0]['metadata']['authors']
    mtdt['supplier'] = sboms[0]['metadata']['supplier']
    mtdt['tools'] = [{"vendor": "Veracode", "name": "SCA SBOM Tool","version": "1.0"}]

    collection_component = {}
    collection_component['type'] = 'application'
    collection_component['group'] = None
    collection_component['bom-ref'] = collection['name']
    collection_component['name'] = collection['name']
    collection_component['version'] = None
    collection_component['purl'] = None
    collection_component['hashes'] = None
    collection_component['licenses'] = None
    collection_component['supplier'] = None

    coll_prop = make_name_value ('Collection Identifier', collection['guid'])
    coll_tags = make_name_value ('Tags', collection['tags'])
    coll_desc = make_name_value ('Description', collection['description'])

    collection_component['properties'] = [coll_prop,coll_desc,coll_tags]
    mtdt['component'] = collection_component
    return mtdt

def make_name_value(name, value):
    the_pair = {}
    the_pair['name'] = name
    the_pair['value'] = value
    return the_pair

def generate_sbom(sboms,collection):
    the_sbom = {}

    # add all vulnerabilities to the vulnerabilities section
    vulns = []
    for sbom in sboms:
        vulns.append(sbom['vulnerabilities'])
    the_sbom['vulnerabilities'] = vulns

    # add all components to the components section
    comps = []
    for sbom in sboms:
        comps.append(sbom['components'])
    the_sbom['components'] = comps

    #add all existing dependencies to the depedencies section
    deps = []
    for sbom in sboms:
        deps.append(sbom['dependencies'])
    the_sbom['dependencies'] = deps

    # generate dependencies between apps and components

    # add application level components to the components list
    for sbom in sboms:
        the_component_app = sbom['metadata']['component']
        the_sbom['components'].append(the_component_app)

    # generate metadata section
    mtdt = make_collection_sbom_metadata(sboms,collection)

    the_sbom['metadata'] = mtdt
    
    return the_sbom

def write_sbom(sbom,this_collection):
    filename = '{}-{}'.format(this_collection['guid'],this_collection['name'])
    with open('{}.json'.format(filename), 'w') as outfile:
        json.dump(sbom,outfile)

def main():
    parser = argparse.ArgumentParser(
        description='This script generates a consolidated CycloneDX SBOM for a Veracode collection.')
    parser.add_argument('-c', '--collectionsid', help='Collections guid to create a report')
    parser.add_argument('-p', '--prompt', action='store_true', help='Prompt for collection using partial match search',default=True)
    args = parser.parse_args()

    collguid = args.collectionsid
    prompt = args.prompt
    setup_logger()

    # CHECK FOR CREDENTIALS EXPIRATION
    creds_expire_days_warning()

    if prompt:
        collguid = prompt_for_collection('Enter the collection name for which to generate an SBOM: ')
        if collguid == "":
            return

    if not(is_valid_uuid(collguid)):
        print('{} is an invalid collection guid. Please supply a valid UUID.'.format(collguid))
        return    

    status = "Getting assets and info for collection {}...".format(collguid)
    log.info(status)
    print(status)
    this_collection = get_collection(collguid)

    assets = get_collection_assets(collguid)

    status = "Getting SBOMs for collection assets..."
    log.info(status)
    print(status)
    sboms = get_sboms(assets)

    status = "Gemerating consolidated SBOM..."
    log.info(status)
    print(status)
    final_sbom = generate_sbom(sboms,this_collection)

    status = "Writing SBOM to file…"
    log.info(status)
    print(status)
    write_sbom(final_sbom,this_collection)

    status = "Created consolidated sbom"
    print(status)
    log.info(status)
    
if __name__ == '__main__':
    main()