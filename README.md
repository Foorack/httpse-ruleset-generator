# httpse-ruleset-generator

This tool is used for automatic ruleset generation for the software [https-everywhere](https://github.com/efforg/https-everywhere).

# Installation
This installation bashscript will prepare dependencies and install required python libraries.

    $ bash setup.sh

# Usage
This program requires python3.4 to run. It should work with other python3 versions however this is untested. Please remember to manually review the generated ruleset before submitting.

    python3 ruleset-generator.py <domain> "<website name>"
    
Example:

    python3 ruleset-generator.py eff.org "Electronic Frontier Foundation"
    
# Roadmap

[X] Step 1: Create prototype as working example.
[ ] Step 2: Stabilise and finish for general use.
[ ] Step 3: Possibly merge into the main EFForg/https-everywhere project.

# To-Do List

[ ] Clean up code
[X] Proper argument handling
[ ] Improve mixed-content checks
[ ] Improve different-content checks
[X] Check if http redirects to other domain
