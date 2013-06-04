def getReferencesList(root):
    ref_list = []
    for defs in root.findall('./{%s}references/{%s}source'%(nsap['vuln'], nsap['vuln'])):
        ref_list.append(defs.text)
    return ref_list
        
def getCVSSDict(root):
    cvss = {}
    for defs in root.findall('./{%s}cvss/{%s}base_metrics//'%(nsap['vuln'], nsap['cvss'])):
        st = defs.tag
        st = st[st.find('}') + 1 : ]
        cvss[st] = defs.text
    return cvss
       
def getDatePublishedDict(root):
    return root.find('./{%s}published-datetime'%nsap['vuln']).text
        
def getDateUpdatedDict(root):
    return root.find('./{%s}last-modified-datetime'%nsap['vuln']).text
        
def getCPEList(root):
    cpe_list = []
    for defs in root.findall('./{%s}vulnerable-software-list/{%s}product'%(nsap['vuln'], nsap['vuln'])):
        cpe = {}
        st = defs.text
        st_list = st.split(':')[2 : ]
        attr_list = ['vendor', 'product', 'version', 'update', 'edition', 'language']
        cpe = dict(zip(attr_list,st_list))
        cpe_list.append(cpe)
    return cpe_list

def getDescription(root):
    return root.find('./{%s}summary'%nsap['vuln']).text





    
try:
    from lxml import etree as ET
    from pprint import pprint
    import logging
    import logging.config
    import ConfigParser
    from tables import Vulnerabilities,CVSS,Reference_Types,References,ObjectLinks,ObjectVersions,ObjectVendors,ObjectProducts,ObjectCorrelation
    import sqlalchemy
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.ext.declarative import declarative_base
    from tables import Base
    #Base = declarative_base()
except ImportError:
    print 'Error occured in importing the reqiured modules...'
else:
    try:    
        logging.config.fileConfig('cve_log.cfg')
        logger=logging.getLogger('root')
    except Exception:
        print 'The requested log file cannot be processed...'
    else:    
        try:
            config=ConfigParser.ConfigParser()
            config.read('cve_input.cfg')
            filename=config.get('inputfile','input')
        except Exception:
            print 'The requested config file cannot be processed...'
        else:
            tree = ET.parse('nvdcve-2.0-recent.xml')
            root = tree.getroot()
            nsap = root.nsmap

            engine = create_engine('sqlite:///:memory:', echo=True)
            Base.metadata.create_all(engine)
            Session = sessionmaker(bind=engine)
            Session = sessionmaker()
            Session.configure(bind=engine)
            session = Session()
            
            dicts = {}
            for entry in root.findall('./{%s}entry'%nsap[None]):
                value = {}
                value['references'] = getReferencesList(entry)
                logger.debug('References added...')
                value['cvss'] = getCVSSDict(entry)
                logger.debug('CVSS added...')
                value['date_published'] = getDatePublishedDict(entry)
                logger.debug('Date published added...')
                value['date_updated'] = getDateUpdatedDict(entry)
                logger.debug('Date Updated added...')
                value['cpe'] = getCPEList(entry)
                logger.debug('CPE added...')
                value['summary'] = getDescription(entry)

                dicts[entry.get('id')] = value
                vuln = Vulnerabilities(osvdb_id = entry.get('id'), create_date = value['date_published'], update_date = value['date_updated'], description = value['summary'])
                #vuln = Vulnerabilities(osvdb_id = entry.get('id'))
                cvss = CVSS(vector = value['cvss'].get('access-vector','NONE'), complexity = value['cvss'].get('access-complexity','NONE'), authentication = value['cvss'].get('authentication','NONE'), confidentiality = value['cvss'].get('confidentiality-impact','NONE'),integrity = value['cvss'].get('integrity-impact','NONE'), availability = value['cvss'].get('availability-impact','NONE'), source = value['cvss'].get('source','NONE'), generated_date = value['cvss'].get('generated-on-datetime','NONE'), score = value['cvss'].get('score','NONE'), vuln_id = vuln.id)
                session.add(vuln)
                session.add(cvss)
                
                for ref in value['references']:
                    ref_type = Reference_Types(name = ref)
                    references=References(value = ref, vuln_id = vuln.id, ext_reference_type_id = ref_type.id)
                    session.add(ref_type)
                    session.add(references)
                    
                lt = value['cpe']
                for ver in lt:
                    o_version = ObjectVersions(name = ver.get('version','NONE'))
                    o_vendor = ObjectVendors(name = ver['vendor'])
                    o_product = ObjectProducts(name = ver['product'])
                    o_correlation = ObjectCorrelation(object_vendor_id = o_vendor.id, object_version_id = o_version.id, object_product_id = o_product.id)
                    o_objectlinks = ObjectLinks(vuln_id = vuln.id, object_correlation_id = o_correlation.id)
                    session.add(o_version)
                    session.add(o_vendor)
                    session.add(o_product)
                    session.add(o_correlation)
                    session.add(o_objectlinks)
                    
                
                
                session.commit()

                
            logger.critical('Printing the dictionary...')
            pprint (dicts)
            logger.critical('Dictionary printed...')
            for c in session.query(Vulnerabilities).order_by(Vulnerabilities.id):
                    print c.osvdb_id
            print Base.metadata
