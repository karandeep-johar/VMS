from sqlalchemy import *
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, backref
from sqlalchemy import Sequence


Base = declarative_base()

#Table definitions
class Vulnerabilities(Base):
    __tablename__ = 'vulnerabilities'

    id = Column(Integer, primary_key = True, autoincrement=True)
    osvdb_id = Column(String)
    create_date = Column(String)
    update_date = Column(String)
    description = Column(String)

#    def __init__(self, osvdb_id, create_date, update_date, description):
#        self.osvdb_id = osvdb_id
#        self.create_date = create_date
#        self.update_date = update_date
#        self.description = description

    def __repr__(self):
        return '<Vulnerabilities (%d, %s, %s, %s, %s)>'%(self.id, self.osvdb_id, self.create_date, self.update_date, self.description)

class CVSS(Base):
    __tablename__ = 'cvss_metrics'
    
    id = Column(Integer, primary_key = True, autoincrement=True)
    vector = Column(String)
    complexity = Column(String)
    authentication = Column(String)
    confidentiality = Column(String)
    integrity = Column(String)
    availability = Column(String)
    source = Column(String)
    generated_date = Column(String)
    score = Column(String)
    vuln_id = Column(Integer, ForeignKey('vulnerabilities.id'))
    vuln_relationship = relationship('Vulnerabilities')
    cve_id = Column(String)
    
    def __repr__(self):
        return '<CVSS_Metrics(%d, %s, %s, %s, %s, %s, %s, %s, %s, %s, %d, %s)>'%(self.id, self.vector, self.complexity, self.authentication, self.confidentiality, self.integrity, self.availability, self.source, self.generated_date, self.score, self.vuln_id, self.cve_id)

class Reference_Types(Base):
    __tablename__ = 'ext_reference_types'

    id = Column(Integer, primary_key = True, autoincrement=True)
    name = Column(String)

    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return '<ext_reference_types (%d, %s)>'%(self.id, self.name)

class References(Base):
    __tablename__ = 'ext_references'

    id = Column(Integer, primary_key = True, autoincrement=True)
    vuln_id = Column(Integer, ForeignKey('vulnerabilities.id'))
    vuln_relationship = relationship('Vulnerabilities')
    ext_reference_type_id = Column(Integer, ForeignKey('ext_reference_types.id'))
    ext_reference_types_relationship = relationship('Reference_Types')
    value = Column(String)

    def __repr__(self):
        return '<ext_references (%d, %d, %s)>'%(self.vuln_id, self.ext_reference_type_id, self.value)
    
class ObjectLinks(Base):
    __tablename__ = 'object_links'

    id = Column(Integer, primary_key = True, autoincrement=True)
    vuln_id = Column(Integer, ForeignKey('vulnerabilities.id'))
    vuln_relationship = relationship('Vulnerabilities')
    object_correlation_id = Column(Integer, ForeignKey('object_correlation.id'))
    object_correlation_relationship = relationship('ObjectCorrelation')
    def __repr__(self):
        return '<object_links (%d, %d)>'%(self.vuln_id, self.object_correlation_id)
    
class ObjectVersions(Base):
    __tablename__ = 'object_versions'

    id = Column(Integer, primary_key = True, autoincrement=True)
    name = Column(String)
    
    def __repr__(self):
        return '<object_versions (%s)>' % self.name

class ObjectVendors(Base):
    __tablename__ = 'object_vendors'

    id = Column(Integer, primary_key = True, autoincrement=True)
    name = Column(String)
    
    def __repr__(self):
        return '<object_vendors (%s)>' % self.name

class ObjectProducts(Base):
    __tablename__ = 'object_products'

    id = Column(Integer, primary_key = True, autoincrement=True)
    name = Column(String)
    
    def __repr__(self):
        return '<object_products (%s)>' % self.name

class ObjectCorrelation(Base):
    __tablename__ = 'object_correlation'

    id = Column(Integer, primary_key = True, autoincrement=True)
    object_vendor_id = Column(Integer, ForeignKey('object_vendors.id'))
    object_vendor_relationship = relationship('ObjectVendors')
    object_product_id = Column(Integer, ForeignKey('object_products.id'))
    object_product_relationship = relationship('ObjectProducts')
    object_version_id = Column(Integer, ForeignKey('object_versions.id'))
    object_version_relationship = relationship('ObjectVersions')

    def __repr__(self):
        return '<object_correlation (%d, %d, %d)>'%(self.object_vendor_id, self.object_product_id, self.object_version_id)
