# REWRITE IN PROCESS. DUE TO THE COMPLEXITY OF THIS PROJECT I'M REWRITING IT FOR THE THIRD TIME. BASIC SCHEMATIC BELOW. CONTRIBUTIONS ARE WELCOMED
![Chart](https://i.imgur.com/iem3O4y.png)

# httpse-ruleset-generator

This tool is used for automatic ruleset generation for the software - [https-everywhere](https://github.com/efforg/https-everywhere).
Old version 2 can be found in old-ruleset-generator.py. The new version 3 is being written in ruleset-generator.py.

# Installation
This installation bashscript will prepare dependencies and install required python libraries.

    $ bash setup.sh

# Usage
This program requires python3.4 to run. It should work with other python3 versions however this is untested. Please remember to manually review the generated ruleset before submitting.

    python3 ruleset-generator.py -d <domain> -n "<website name>"

Example:

    python3 ruleset-generator.py -d eff.org -n "Electronic Frontier Foundation"

Full list of arguments:

    -d  --domain    Domain to generate ruleset about, TLD, do not include www
    -n  --name      Label the ruleset with a custom name, for example "Electronic Frontier Foundation"
    -t  --timeout   Define timeout value, this might be neccesary on slower internet connections
    -v  --verbose   Enable verbosity and print debug data in realtime
    
# Roadmap

- [X] Step 1: Create prototype as working example.
- [ ] Step 2: Stabilise and finish for general use.
- [ ] Step 3: Possibly merge into the main EFForg/https-everywhere project.

# To-Do List New

- [X] Implement basic structure, see flowchart
- [X] Proper argument handling
- [X] Implement mixed-content checks
- [ ] Implement different-content checks
- [ ] Print out results to xml file
- [ ] Implement summary report logic
- [ ] Add missing function documenation

# License
This code is being written and released under 
GNU GENERAL PUBLIC LICENSE Version 3. Please see [LICENSE File](LICENSE) 
for more information.