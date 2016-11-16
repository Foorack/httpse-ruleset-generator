# httpse-ruleset-generator

This tool is used for automatic ruleset generation for the software [https-everywhere](https://github.com/efforg/https-everywhere).

# Installation
This installation bashscript will prepear dependencies and install required python libraries.

    $ bash setup.sh

# Usage
This program requires python3.4 to run. It should work with other python3 versions however this is untested. Please remember to manually review the generated ruleset before submitting.

    python3 ruleset-generator.py <domain> "<website name>"
    
Example:

    python3 ruleset-generator.py eff.org "Electronic Frontier Foundation"
    
# Roadmap

[X] Step 1: Create prototype as working example.
[ ] Step 2: Stablise and finish for general use.
[ ] Step 3: Possbily merge into the main EFForg/https-everywhere project.

# To-Do List

[] Modulise the code
[] Proper argument handling
[] Improve mixed-content checks
[] Improve different-content checks
[] Check if http redirects to other domain