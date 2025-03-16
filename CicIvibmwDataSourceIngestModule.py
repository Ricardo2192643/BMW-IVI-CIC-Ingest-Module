# Sample module in the public domain. Feel free to use this as a template
# This software is free, you can use and modify
#
# Create ingest module by Ricardo Marques Master's student in Cybersecurity and Forensic Informatics
# Polytechnic Institute of Leiria - Portugal
#
# This ingest module allows you to investigate SQLite database of
# BMW brand In-Vehicle Infotainment systems CIC model year 2010 and 2012
# Find data such as contacts
# Bluetooth mac address
# which devices were connected
#
#
# This ingest module was used Autopsy version 4.18.0
#
# Instructions for using this ingest module:
# Tools - Python Plugins and put ingest module in that folder
#
#


import jarray
import inspect
import os
from java.lang import Class
from java.lang import System
from java.sql  import DriverManager, SQLException
from java.util.logging import Level
from java.util import ArrayList
from java.io import File
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.datamodel import ContentUtils
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.autopsy.casemodule.services import Blackboard


# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the analysis.
# Rename this to something more specific. Search and replace for it because it is used a few times
class CicIviBmwDbIngestModuleFactory(IngestModuleFactoryAdapter):

    # TODO: give it a unique name.
    moduleName = "Infotainment BMW CIC"

    def getModuleDisplayName(self):
        return self.moduleName

    # TODO: Give it a description
    def getModuleDescription(self):
        return "extract phone numbers,email,address,country,bluetooth,macaddress,devices were connected"
     
    def getModuleVersionNumber(self):
        return "1.0"

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        #Change the class name to the name you'll make below
        return CicIviBmwDbIngestModule()


#Data Source-level ingest module.  One gets created per data source.
#Rename this to something more specific.
class CicIviBmwDbIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(CicIviBmwDbIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self):
        self.context = None

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/4.4/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    # Add any setup code that you need here.
    def startUp(self, context):
        
        # Throw an IngestModule.IngestModuleException exception if there was a problem setting up
        
        self.context = context

    # Where the analysis is done.
    # The 'dataSource' object being passed in is of type org.sleuthkit.datamodel.Content.
    # See: http://www.sleuthkit.org/sleuthkit/docs/jni-docs/4.4/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    # 'progressBar' is of type org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress
    # See: http://sleuthkit.org/autopsy/docs/api-docs/4.4/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_data_source_ingest_module_progress.html
    # Add your analysis code in here.
    def process(self, dataSource, progressBar):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()

        # Use blackboard class to index blackboard artifacts for keyword search
        blackboard = Case.getCurrentCase().getServices().getBlackboard()

        # Find files named contactbook, regardless of parent path
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "contactbook_%.db")

        numFiles = len(files)
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0
        for file in files:

            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Save the DB locally in the temp folder. use file id as name to reduce collisions
            lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory(), str(file.getId()) + ".db")
            ContentUtils.writeToFile(file, File(lclDbPath))
                        
            # Open the DB using JDBC
            try: 
                Class.forName("org.sqlite.JDBC").newInstance()
                dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
            except SQLException as e:
                self.log(Level.INFO, "Could not open database file (not SQLite) " + file.getName() + " (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK
            
            # Query the contacts table in the database and get all columns. 
            try:
                stmt = dbConn.createStatement()
                resultSet = stmt.executeQuery("SELECT contact_card_phone.Contact_ID, "
                                    "contact_card_phone.GivenName, contact_card_phone.FamilyName, "
                                    "contact_card_phone.organisation FROM contact_card_phone "
                                    "ORDER BY contact_card_phone.GivenName")
            except SQLException as e:
                self.log(Level.INFO, "Error querying database for contacts table (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK

            # Cycle through each row and create artifacts
            while resultSet.next():
                try: 
                    Contact_ID = resultSet.getString("Contact_ID")
                    GivenName = resultSet.getString("GivenName")
                    FamilyName = resultSet.getString("FamilyName")
                    organisation = resultSet.getString("organisation")
                    
                    
                except SQLException as e:
                    self.log(Level.INFO, "Error getting values from contacts table (" + e.getMessage() + ")")
                
                
                # Make an artifact on the blackboard, TSK_CONTACT and give it attributes for each of the fields
                art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_CONTACT)
                family_name_att_type = blackboard.getOrAddAttributeType('BMW_FAMILY_NAME_TYPE',BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "FamilyName")
                attributes = ArrayList()
                
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_USER_ID.getTypeID(), CicIviBmwDbIngestModuleFactory.moduleName, Contact_ID))
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NAME.getTypeID(), CicIviBmwDbIngestModuleFactory.moduleName, GivenName))
                attributes.add(BlackboardAttribute(family_name_att_type,CicIviBmwDbIngestModuleFactory.moduleName, FamilyName))
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_ORGANIZATION.getTypeID(), CicIviBmwDbIngestModuleFactory.moduleName, organisation))
                
                
                
                        
                art.addAttributes(attributes)
                try:
                    # index the artifact for keyword search
                    blackboard.indexArtifact(art)
                except Blackboard.BlackboardException as e:
                    self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())
        
        #database conctactbook search contact phone
        
        files = fileManager.findFiles(dataSource, "contactbook_%.db")

        arttttId = blackboard.getOrAddArtifactType("TSK_CONTACT_PHONE", "Contact Phone")
        
        numFiles = len(files)
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0
        for file in files:

            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Save the DB locally in the temp folder. use file id as name to reduce collisions
            lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory(), str(file.getId()) + ".db")
            ContentUtils.writeToFile(file, File(lclDbPath))
                        
            # Open the DB using JDBC
            try: 
                Class.forName("org.sqlite.JDBC").newInstance()
                dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
            except SQLException as e:
                self.log(Level.INFO, "Could not open database file (not SQLite) " + file.getName() + " (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK
            
            # Query the contact phone table in the database and get all columns. 
            try:
                stmt = dbConn.createStatement()
                resultSet = stmt.executeQuery("SELECT contact_card_phone.Contact_ID, contact_card_phone.GivenName, "
								  "contact_card_phone.FamilyName,"
								  "phone_data_phone.PhoneNumber FROM contact_card_phone "
								  "JOIN phone_data_phone ON contact_card_phone.Contact_ID = phone_data_phone.Contact_ID "
                                  "ORDER BY contact_card_phone.GivenName")
            except SQLException as e:
                self.log(Level.INFO, "Error querying database for contacts table (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK

            # Cycle through each row and create artifacts
            while resultSet.next():
                try: 
                    Contact_ID = resultSet.getString("Contact_ID")
                    GivenName = resultSet.getString("GivenName")
                    FamilyName = resultSet.getString("FamilyName")
                    PhoneNumber = resultSet.getString("PhoneNumber")

                    
                except SQLException as e:
                    self.log(Level.INFO, "Error getting values from contacts table (" + e.getMessage() + ")")
                
                
                # Make an artifact on the blackboard, TSK_CONTACT and give it attributes for each of the fields
                art = file.newArtifact(arttttId.getTypeID())
                family_name_att_type = blackboard.getOrAddAttributeType('BMW_FAMILY_NAME_TYPE',BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "FamilyName")
                attributes = ArrayList()
                
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_USER_ID.getTypeID(), CicIviBmwDbIngestModuleFactory.moduleName, Contact_ID))
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NAME.getTypeID(), CicIviBmwDbIngestModuleFactory.moduleName, GivenName))
                attributes.add(BlackboardAttribute(family_name_att_type,CicIviBmwDbIngestModuleFactory.moduleName, FamilyName)) 
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PHONE_NUMBER.getTypeID(), CicIviBmwDbIngestModuleFactory.moduleName, PhoneNumber))

                           
                art.addAttributes(attributes)
                try:
                    # index the artifact for keyword search
                    blackboard.indexArtifact(art)
                except Blackboard.BlackboardException as e:
                    self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())

        #database contactbook search contact email
        files = fileManager.findFiles(dataSource, "contactbook_%.db")

        arttttIId = blackboard.getOrAddArtifactType("TSK_CONTACT_EMAIL", "Contact Email")
        
        numFiles = len(files)
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0
        for file in files:

            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Save the DB locally in the temp folder. use file id as name to reduce collisions
            lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory(), str(file.getId()) + ".db")
            ContentUtils.writeToFile(file, File(lclDbPath))
                        
            # Open the DB using JDBC
            try: 
                Class.forName("org.sqlite.JDBC").newInstance()
                dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
            except SQLException as e:
                self.log(Level.INFO, "Could not open database file (not SQLite) " + file.getName() + " (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK
            
            # Query the contact email table in the database and get all columns. 
            try:
                stmt = dbConn.createStatement()
                resultSet = stmt.executeQuery("SELECT contact_card_phone.Contact_ID, contact_card_phone.GivenName, "
								  "contact_card_phone.FamilyName, msg_data_phone.EmailAddr FROM contact_card_phone "								  
					              "JOIN msg_data_phone ON contact_card_phone.Contact_ID = msg_data_phone.Contact_ID "								  
								  "ORDER BY contact_card_phone.GivenName")
            except SQLException as e:
                self.log(Level.INFO, "Error querying database for contacts table (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK

            # Cycle through each row and create artifacts
            while resultSet.next():
                try: 
                    Contact_ID = resultSet.getString("Contact_ID")
                    GivenName = resultSet.getString("GivenName")
                    FamilyName = resultSet.getString("FamilyName")
                    EmailAddr = resultSet.getString("EmailAddr")
                    
                    
                except SQLException as e:
                    self.log(Level.INFO, "Error getting values from contacts table (" + e.getMessage() + ")")
                
                
                # Make an artifact on the blackboard, TSK_CONTACT_EMAIL and give it attributes for each of the fields
                art = file.newArtifact(arttttIId.getTypeID())
                family_name_att_type = blackboard.getOrAddAttributeType('BMW_FAMILY_NAME_TYPE',BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "FamilyName")
                attributes = ArrayList()
                
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_USER_ID.getTypeID(), CicIviBmwDbIngestModuleFactory.moduleName, Contact_ID))
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NAME.getTypeID(), CicIviBmwDbIngestModuleFactory.moduleName, GivenName))
                attributes.add(BlackboardAttribute(family_name_att_type,CicIviBmwDbIngestModuleFactory.moduleName, FamilyName))
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_EMAIL.getTypeID(), CicIviBmwDbIngestModuleFactory.moduleName, EmailAddr))
               

                
                           
                art.addAttributes(attributes)
                try:
                    # index the artifact for keyword search
                    blackboard.indexArtifact(art)
                except Blackboard.BlackboardException as e:
                    self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())
                          
        #database contactbook search contact address
        files = fileManager.findFiles(dataSource, "contactbook_%.db")

        arttttIIId = blackboard.getOrAddArtifactType("TSK_CONTACT_ADDRESS", "Contact Address")
        
        numFiles = len(files)
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0
        for file in files:

            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Save the DB locally in the temp folder. use file id as name to reduce collisions
            lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory(), str(file.getId()) + ".db")
            ContentUtils.writeToFile(file, File(lclDbPath))
                        
            # Open the DB using JDBC
            try: 
                Class.forName("org.sqlite.JDBC").newInstance()
                dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
            except SQLException as e:
                self.log(Level.INFO, "Could not open database file (not SQLite) " + file.getName() + " (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK
            
            # Query the contact address table in the database and get all columns. 
            try:
                stmt = dbConn.createStatement()
                resultSet = stmt.executeQuery("SELECT contact_card_phone.Contact_ID, contact_card_phone.GivenName, "
								  "contact_card_phone.FamilyName, "			
								  "address_phone.StreetHousenumber, address_phone.City, "
								  "address_phone.Country, address_phone.Postalcode FROM contact_card_phone "
								  "JOIN address_phone ON contact_card_phone.Contact_ID = address_phone.Contact_ID "
                                  "WHERE address_phone.crosssum > 0 "
								  "ORDER BY contact_card_phone.GivenName")
            except SQLException as e:
                self.log(Level.INFO, "Error querying database for contacts table (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK

            # Cycle through each row and create artifacts
            while resultSet.next():
                try: 
                    Contact_ID = resultSet.getString("Contact_ID")
                    GivenName = resultSet.getString("GivenName")
                    FamilyName = resultSet.getString("FamilyName")
                    StreetHousenumber = resultSet.getString("StreetHousenumber")
                    City = resultSet.getString("City")
                    Country = resultSet.getString("Country")
                    Postalcode = resultSet.getString("Postalcode")
                    
                except SQLException as e:
                    self.log(Level.INFO, "Error getting values from contacts table (" + e.getMessage() + ")")
                
                
                # Make an artifact on the blackboard, TSK_CONTACT_ADDRESS and give it attributes for each of the fields
                art = file.newArtifact(arttttIIId.getTypeID())
                postal_code_att_type = blackboard.getOrAddAttributeType('BMW_POSTAL_CODE_TYPE',BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "PostalCode")
                family_name_att_type = blackboard.getOrAddAttributeType('BMW_FAMILY_NAME_TYPE',BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "FamilyName")

                attributes = ArrayList()
                
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_USER_ID.getTypeID(), CicIviBmwDbIngestModuleFactory.moduleName, Contact_ID))
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NAME.getTypeID(), CicIviBmwDbIngestModuleFactory.moduleName, GivenName))
                attributes.add(BlackboardAttribute(family_name_att_type,CicIviBmwDbIngestModuleFactory.moduleName, FamilyName)) 
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_LOCATION.getTypeID(), CicIviBmwDbIngestModuleFactory.moduleName, StreetHousenumber))
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_CITY.getTypeID(), CicIviBmwDbIngestModuleFactory.moduleName, City))
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_COUNTRY.getTypeID(), CicIviBmwDbIngestModuleFactory.moduleName, Country))
                attributes.add(BlackboardAttribute(postal_code_att_type,CicIviBmwDbIngestModuleFactory.moduleName, Postalcode)) 
                

                
                           
                art.addAttributes(attributes)
                try:
                    # index the artifact for keyword search
                    blackboard.indexArtifact(art)
                except Blackboard.BlackboardException as e:
                    self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())
                       
        #database contactbook search bluetooth
        
        files = fileManager.findFiles(dataSource, "contactbook_2010%.db")

        numFiles = len(files)
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0
        for file in files:

            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Save the DB locally in the temp folder. use file id as name to reduce collisions
            lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory(), str(file.getId()) + ".db")
            ContentUtils.writeToFile(file, File(lclDbPath))
                        
            # Open the DB using JDBC
            try: 
                Class.forName("org.sqlite.JDBC").newInstance()
                dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
            except SQLException as e:
                self.log(Level.INFO, "Could not open database file (not SQLite) " + file.getName() + " (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK
            
            # Query the bluetooth table in the database and get all columns. 
            try:
                stmt = dbConn.createStatement()
                resultSet = stmt.executeQuery("SELECT Bt_ID, HEX(Bt_address) as hexBt from bluetooth")
            except SQLException as e:
                self.log(Level.INFO, "Error querying database for contacts table (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK

            # Cycle through each row and create artifacts
            while resultSet.next():
                try: 
                    Bt_ID = resultSet.getString("Bt_ID")
                    self.log(Level.INFO, "Bt_ID" + Bt_ID)
                    Bt_address = resultSet.getString("hexBt")
                    self.log(Level.INFO, "Bt_address" + Bt_address)
                    
                    # Make an artifact on the blackboard, TSK_BLUETOOTH_PAIRING and give it attributes for each of the fields
                    art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_BLUETOOTH_PAIRING)
                    bluetooth_address_att_type = blackboard.getOrAddAttributeType('BMW_BLUETOOTH_ADDRESS_TYPE',BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Bt_address")

                    attributes = ArrayList()
                    attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_ID.getTypeID(), CicIviBmwDbIngestModuleFactory.moduleName, Bt_ID))
                    attributes.add(BlackboardAttribute(bluetooth_address_att_type,CicIviBmwDbIngestModuleFactory.moduleName, Bt_address)) 

                    art.addAttributes(attributes)
                    try:
                        Case.getCurrentCase().getSleuthkitCase().getBlackboard().postArtifact(art, CicIviBmwDbIngestModuleFactory.moduleName)
                    except Blackboard.BlackboardException as e:
                        self.log(Level.SEVERE, "Error posting artifact " + art.getDisplayName())
                    
                except SQLException as e:
                    self.log(Level.INFO, "Error getting values from contacts table (" + e.getMessage() + ")")
            
        
        
        
        #mme database
        #mediastores
        
        files = fileManager.findFiles(dataSource, "mme")

        numFiles = len(files)
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0
        for file in files:

            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Save the DB locally in the temp folder. use file id as name to reduce collisions
            lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory(), str(file.getId()) + ".db" )
            ContentUtils.writeToFile(file, File(lclDbPath))
                        
            # Open the DB using JDBC
            try: 
                Class.forName("org.sqlite.JDBC").newInstance()
                dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
            except SQLException as e:
                self.log(Level.INFO, "Could not open database file (not SQLite) " + file.getName() + " (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK
            
            # Query the mediastores table in the database and get all columns. 
            try:
                stmt = dbConn.createStatement()
                resultSet = stmt.executeQuery("SELECT msid, capabilities, mssname, name, identifier, mountpath FROM mediastores")

                # Cycle through each row and create artifacts
                while resultSet.next():
                    try: 
                        msid = resultSet.getString("msid") 
                        capabilities = resultSet.getLong("capabilities")
                        mssname = resultSet.getString("mssname")
                        name = resultSet.getString("name")
                        identifier = resultSet.getString("identifier")
                        mountpath = resultSet.getString("mountpath")
                    
                        
                    except SQLException as e:
                        self.log(Level.INFO, "Error getting values from contacts table (" + e.getMessage() + ")")                
                    
                    # Make an artifact on the blackboard, TSK_DEVICE_INFO and give it attributes for each of the fields
                    art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_DEVICE_INFO)
                    attributes = ArrayList()
                    attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_ID.getTypeID(), CicIviBmwDbIngestModuleFactory.moduleName, msid))
                    timevalue = capabilities/1000000000
                    attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME.getTypeID(), CicIviBmwDbIngestModuleFactory.moduleName, timevalue))
                    attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DESCRIPTION.getTypeID(), CicIviBmwDbIngestModuleFactory.moduleName, mssname))
                    attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NAME.getTypeID(), CicIviBmwDbIngestModuleFactory.moduleName, name))
                    attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DEVICE_ID.getTypeID(), CicIviBmwDbIngestModuleFactory.moduleName, identifier))
                    attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PATH.getTypeID(), CicIviBmwDbIngestModuleFactory.moduleName, mountpath))
                
                    art.addAttributes(attributes)
                    
                    try:
                        # index the artifact for keyword search
                        blackboard.indexArtifact(art)
                    except Blackboard.BlackboardException as e:
                        self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())
                    
            except SQLException as e:
                self.log(Level.INFO, "Error querying database " +file.getParentPath()+file.getName() + " table (" + e.getMessage() + "). Ignoring this file and continuing ingest.")
                #Miguel: esta instrucao deixa de ser necessaria.
                #return IngestModule.ProcessResult.OK

        

        #mme database
        #software info
        files = fileManager.findFiles(dataSource, "%mme_custom")

        artIId = blackboard.getOrAddArtifactType("TSK_SOFTWARE_INFO", "Software info")
        numFiles = len(files)
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0
        for file in files:

            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Save the DB locally in the temp folder. use file id as name to reduce collisions
            lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory(), str(file.getId()) + ".db" )
            ContentUtils.writeToFile(file, File(lclDbPath))
                        
            # Open the DB using JDBC
            try: 
                Class.forName("org.sqlite.JDBC").newInstance()
                dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
            except SQLException as e:
                self.log(Level.INFO, "Could not open database file (not SQLite) " + file.getName() + " (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK
            
            # Query the software info table in the database and get all columns. 
            try:
                stmt = dbConn.createStatement()
                resultSet = stmt.executeQuery("SELECT version FROM software_info")
            except SQLException as e:
                self.log(Level.INFO, "Error querying database for contacts table (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK

            # Cycle through each row and create artifacts
            while resultSet.next():
                try: 
                    version = resultSet.getString("version")
                    
                   
                    
                except SQLException as e:
                    self.log(Level.INFO, "Error getting values from contacts table (" + e.getMessage() + ")")                
                
                # Make an artifact on the blackboard, TSK_SOFTWARE_INFO and give it attributes for each of the fields
                art = file.newArtifact(artIId.getTypeID())
                attributes = ArrayList()
               
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_VERSION.getTypeID(), CicIviBmwDbIngestModuleFactory.moduleName, version))
               
                art.addAttributes(attributes)
                try:
                    # index the artifact for keyword search
                    blackboard.indexArtifact(art)
                except Blackboard.BlackboardException as e:
                    self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())
                
        #mme library folders
        files = fileManager.findFiles(dataSource, "%mme_library")

        artIIIId = blackboard.getOrAddArtifactType("TSK_FOLDERS", "Folders")
        numFiles = len(files)
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0
        for file in files:

            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Save the DB locally in the temp folder. use file id as name to reduce collisions
            lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory(), str(file.getId()) + ".db" )
            ContentUtils.writeToFile(file, File(lclDbPath))
                        
            # Open the DB using JDBC
            try: 
                Class.forName("org.sqlite.JDBC").newInstance()
                dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
            except SQLException as e:
                self.log(Level.INFO, "Could not open database file (not SQLite) " + file.getName() + " (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK
            
            # Query the library folders table in the database and get all columns. 
            try:
                stmt = dbConn.createStatement()
                resultSet = stmt.executeQuery("SELECT foldername, last_sync, basepath FROM folders")
            except SQLException as e:
                self.log(Level.INFO, "Error querying database for contacts table (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK

            # Cycle through each row and create artifacts
            while resultSet.next():
                try: 
                    foldername = resultSet.getString("foldername")
                    last_sync = resultSet.getLong("last_sync")
                    basepath = resultSet.getString("basepath")
                    
                   
                    
                except SQLException as e:
                    self.log(Level.INFO, "Error getting values from contacts table (" + e.getMessage() + ")")                
                
                # Make an artifact on the blackboard, TSK_FOLDERS and give it attributes for each of the fields
                art = file.newArtifact(artIIIId.getTypeID())
                folder_name_att_type = blackboard.getOrAddAttributeType('BMW_FOLDER_NAME_TYPE',BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "foldername")
                
                attributes = ArrayList()
                
                attributes.add(BlackboardAttribute(folder_name_att_type,CicIviBmwDbIngestModuleFactory.moduleName, foldername)) 
                timevalue = last_sync/1000000000
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_MODIFIED.getTypeID(), CicIviBmwDbIngestModuleFactory.moduleName, timevalue))
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PATH.getTypeID(), CicIviBmwDbIngestModuleFactory.moduleName, basepath))

               
                art.addAttributes(attributes)
                try:
                    # index the artifact for keyword search
                    blackboard.indexArtifact(art)
                except Blackboard.BlackboardException as e:
                    self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())
                        
        #Library albuns

        files = fileManager.findFiles(dataSource, "mme_library%")

        artIIIIId = blackboard.getOrAddArtifactType("TSK_LIBRARY_ALBUNS", "Library albums")

        numFiles = len(files)
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0
        for file in files:

            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Save the DB locally in the temp folder. use file id as name to reduce collisions
            lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory(), str(file.getId()) + ".db" )
            ContentUtils.writeToFile(file, File(lclDbPath))
                        
            # Open the DB using JDBC
            try: 
                Class.forName("org.sqlite.JDBC").newInstance()
                dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
            except SQLException as e:
                self.log(Level.INFO, "Could not open database file (not SQLite) " + file.getName() + " (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK
            
            # Query the Library albuns table in the database and get all columns. 
            try:
                stmt = dbConn.createStatement()
                resultSet = stmt.executeQuery("SELECT library_albums.album FROM library_albums")
            except SQLException as e:
                self.log(Level.INFO, "Error querying database for contacts table (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK

            # Cycle through each row and create artifacts
            while resultSet.next():
                try: 
                    album = resultSet.getString("album")
                    
                    
                except SQLException as e:
                    self.log(Level.INFO, "Error getting values from contacts table (" + e.getMessage() + ")")                
                
                # Make an artifact on the blackboard, TSK_LIBRARY_ALBUNS and give it attributes for each of the fields
                art = file.newArtifact(artIIIIId.getTypeID())
                library_albums_att_type = blackboard.getOrAddAttributeType('BMW_LIBRARY_ALBUMS_TYPE',BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "album")
                attributes = ArrayList()
                
                attributes.add(BlackboardAttribute(library_albums_att_type,CicIviBmwDbIngestModuleFactory.moduleName, album)) 

                art.addAttributes(attributes)
                try:
                    # index the artifact for keyword search
                    blackboard.indexArtifact(art)
                except Blackboard.BlackboardException as e:
                    self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())
                
        #Library artists
        files = fileManager.findFiles(dataSource, "%mme_library%")
        artIIIIIId = blackboard.getOrAddArtifactType("TSK_LIBRARY_ARTISTS", "Library artists")

        numFiles = len(files)
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0
        for file in files:

            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Save the DB locally in the temp folder. use file id as name to reduce collisions
            lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory(), str(file.getId()) + ".db" )
            ContentUtils.writeToFile(file, File(lclDbPath))
                        
            # Open the DB using JDBC
            try: 
                Class.forName("org.sqlite.JDBC").newInstance()
                dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
            except SQLException as e:
                self.log(Level.INFO, "Could not open database file (not SQLite) " + file.getName() + " (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK
            
            # Query the Library artists table in the database and get all columns. 
            try:
                stmt = dbConn.createStatement()
                resultSet = stmt.executeQuery("SELECT library_artists.artist FROM library_artists")
            except SQLException as e:
                self.log(Level.INFO, "Error querying database for contacts table (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK

            # Cycle through each row and create artifacts
            while resultSet.next():
                try: 
                    artist = resultSet.getString("artist")
                    
                    
                except SQLException as e:
                    self.log(Level.INFO, "Error getting values from contacts table (" + e.getMessage() + ")")                
                
                # Make an artifact on the blackboard, TSK_LIBRARY_ARTISTS and give it attributes for each of the fields
                art = file.newArtifact(artIIIIIId.getTypeID())
                library_artists_att_type = blackboard.getOrAddAttributeType('BMW_LIBRARY_ARTISTS_TYPE',BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "artist")
                attributes = ArrayList()
                
                attributes.add(BlackboardAttribute(library_artists_att_type,CicIviBmwDbIngestModuleFactory.moduleName, artist)) 

                art.addAttributes(attributes)
                try:
                    # index the artifact for keyword search
                    blackboard.indexArtifact(art)
                except Blackboard.BlackboardException as e:
                    self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())  

        #Post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "Sample Jython Data Source Ingest Module", "Found %d files" % fileCount)
        IngestServices.getInstance().postMessage(message)
        
        return IngestModule.ProcessResult.OK
