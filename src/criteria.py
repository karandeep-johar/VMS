def getTitle(root): #input:definition, output:title
    root1 = root.find('./{%s}metadata/{%s}title'%(nsap[None], nsap[None]))
    return root1.text

def getDescription(root): #input:definition, output:description
    root1 = root.find('./{%s}metadata/{%s}description'%(nsap[None], nsap[None]))
    return root1.text.encode('ascii','replace')

def getListCVE(root): #input:definition, output:List of CVE text
    list_cve = []
    for tmp in root.findall('./{%s}metadata/{%s}advisory/{%s}cve'%(nsap[None], nsap[None], nsap[None])):
        list_cve.append(tmp.text)
    return list_cve

def getReferences(root): #input:definition, output:dictionary with key as references and value as list of cve, bugzilla and third party ids
    ref_dict = {}
    ref_dict['cve'] = getListCVE(root)
    for tmp in root.findall('./{%s}metadata/{%s}advisory//*[@id]'%(nsap[None], nsap[None])):
        st = tmp.tag
        st = st[st.find('}') + 1 : ]
        if(st not in ref_dict):
            ref_dict[st]=[]
        ref_dict[st].append(tmp.get('id'))
    return ref_dict

def getAffectedDict(root): #input:definition, output:Dictionary with key as affected packages and value as versions
    aff_dict = {}
    for tmp in root.findall('./{%s}criteria//{%s}criterion'%(nsap[None], nsap[None])):
        st = tmp.get('comment')
        if st.find('Red Hat Enterprise') != 0:
            ind = st.find('is earlier than')
            if ind != -1:
                aff_dict[st[ : st.find(' is ')]] = st[ind + len('is earlier than')+1 : ]
    return aff_dict
    

try:
    import logging
    import logging.config
    import ConfigParser
    from pprint import pprint
    from lxml import etree as ET
except ImportError:
    print 'Error occured in importing the reqiured modules...'
else:
    try:    
        logging.config.fileConfig('log.cfg')
        logger=logging.getLogger('root')
    except Exception:
        print 'The requested log file cannot be processed...'
    else:    
        try:
            config=ConfigParser.ConfigParser()
            config.read('input.cfg')
            filename=config.get('inputfile','input')
        except Exception:
            print 'The requested config file cannot be processed...'
        else:
            tree = ET.parse(filename)
            root = tree.getroot()
            nsap = root.nsmap
            
            dicts = {} #dictionary with key as definition id and value as dictionary of the details of definition
            for defs in root.findall('./{%s}definitions/{%s}definition'%(nsap[None], nsap[None])):
                value = {}
                value['title'] = getTitle(defs)
                logger.critical('Title added')
                value['description'] = getDescription(defs)
                logger.critical('Description added')
                value['references'] = getReferences(defs)
                logger.critical('References added')
                value['affected'] = getAffectedDict(defs)
                logger.critical('Affected packages added')
                dicts[defs.get('id')] = value

            logger.critical('Printing the dictionary')
            pprint(dicts)
            logger.critical('Dictionary printed')
