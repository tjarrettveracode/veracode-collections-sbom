# Veracode Collections SBOM

Generate a CycloneDX SBOM across multiple applications that are part of a Veracode Collection.

**Note**: The Collections feature is available only to Veracode customers in the Collections Early Adopter program. As the Collections feature is not GA yet, the functionality of the feature will change over time. This script is provided for illustration purposes only.

## Setup

Clone this repository:

    git clone https://github.com/tjarrettveracode/veracode-collections-sbom

Install dependencies:

    cd veracode-collections-sbom
    pip install -r requirements.txt

(Optional) Save Veracode API credentials in `~/.veracode/credentials`

    [default]
    veracode_api_key_id = <YOUR_API_KEY_ID>
    veracode_api_key_secret = <YOUR_API_KEY_SECRET>

## Run

If you have saved credentials as above you can run:

    python vccollections-sbom.py (arguments)

Otherwise you will need to set environment variables:

    export VERACODE_API_KEY_ID=<YOUR_API_KEY_ID>
    export VERACODE_API_KEY_SECRET=<YOUR_API_KEY_SECRET>
    python vccollections-sbom.py (arguments)

Arguments supported include:

* `--collectionsid`, `-c` (required if `--prompt` is not used): Collections guid for which to create a report.
* `--prompt`, `-p` (optional): Specify to be prompted to search by collection name.
