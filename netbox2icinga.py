#!/usr/bin/python

'''
add netbox devices and VMs to ICINGA

device are moved if
- tag "monitor" is present
- primary ip4 address exists

netbox device "role" is created as icinga2 host variable

'''

from icinga2api.client import Client
import json
import yaml
import logging
import logging.config
import pynetbox
import urllib3
import time
urllib3.disable_warnings()

logging.config.dictConfig({
    'version': 1,
    'disable_existing_loggers': True,
})
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)
#logging.basicConfig(level=logging.DEBUG)

def nbConnect(server,token):
    '''
    connects to Netbox API
    requires server and token
    '''
    url = 'http://'+server
    try:
      nb = pynetbox.api(url,token=token,ssl_verify=False)
    except:
      logger.error("cannot connect to netbox")
      #sys.exit('cannot connect to netbox')
    return nb

def clearIcingaHosts():
  '''
  delete icinga hosts
  '''
  for icingaDevice in icingaHosts:
    icingaName = icingaDevice.get('name')
    if not icingaName == 'icinga':
      icinga.objects.delete('Host',icingaName)

def getNetboxPlatforms(n):
  '''
  get all netbox platforms, return role slug to be used for icinga role assignment
  '''
  platforms={}
  plat = nb.dcim.platforms.all()
  for pl in plat:
    p = pl.serialize()
    platforms[str(p.get('id'))] = str(p.get('slug'))
  return platforms

def getNetboxDeviceTypes(n):
  '''
  get all netbox roles, return role slug to be used for icinga role assignment
  '''
  typedict={}
  types = nb.dcim.device_types.all()
  for deviceType in types:
    t = deviceType.serialize()
    typedict[str(t.get('id'))] = str(t.get('slug'))
  return typedict

def getNetboxRoles(n):
  '''
  get all netbox roles, return role slug to be used for icinga role assignment
  '''
  r={}
  roles = nb.dcim.device_roles.all()
  for role in roles:
    rs = role.serialize()
    r[str(rs.get('id'))] = str(rs.get('slug'))
  return r

def checkResult(r):
  '''
  check request result
  '''
  if int(r.get('results')[0].get('code')) == 200:
    logger.debug('SUCCESS')
    return 1
  else:
    logger.error('ERROR')
    return 0

start = time.time()

configFile = 'netbox2icinga.yml'
logger.info("OPEN CONFIG FILE %s" % (configFile))
try:
  with open(configFile, 'r') as data:
    config = yaml.load(data)
    data.close()
except:
  logger.error("MISSING OR UNREADABLE CONFIG %s" % (configFile))

# connect to Icinga
icingaUrl =  config.get('icinga').get('url')
icingaUser = config.get('icinga').get('user')
icingaPass = config.get('icinga').get('password')
icinga = Client(icingaUrl,icingaUser,icingaPass)

# get all icinga hosts - used to avoid creation of existing objecs
logger.info("READING ICINGA OBJECT LIST")
icingaHosts = icinga.objects.list('Host')

# connect to netbox
token=config.get('netbox').get('token')
server = config.get('netbox').get('server')
logger.info("CONNECTING TO NETBOX SERVER %s" % (server))
nb = nbConnect(server,token)

''' 
read all netbox devices
if device has primary_ip add to icinga
'''

logger.info("READING ROLES FROM TO NETBOX SERVER %s" % (server))
roles = getNetboxRoles(nb) # get all netbox roles as a dictionary
logger.info("READING DEVICE TYPES FROM TO NETBOX SERVER %s" % (server))
types = getNetboxDeviceTypes(nb) # get all netbox device types as a dictionary
logger.info("READING PLATFORMS FROM TO NETBOX SERVER %s" % (server))
platforms = getNetboxPlatforms(nb) # get all netbox platforms as a dictionary

logger.info("READING DEVICES AND VMS FROM TO NETBOX SERVER %s" % (server))
netboxDevices = nb.dcim.devices.all() + nb.virtualization.virtual_machines.all()

logger.info("STARTING NETBOX TO ICINGA DEVICES CHECK" )
for devices in netboxDevices:
  device = devices.serialize()
  if device.get('primary_ip4'):
    tags = device.get('tags')
    deviceName = str(device.get('name'))
    logger.debug('WORKING ON %s' % (deviceName))
    
    if 'monitor' in tags: # add device to icinga

      # add netbox tags starting with "_m" to icigna var "services"
      serviceTags = []
      for tag in tags:
        if tag.startswith('m_'):
          serviceTags.append(tag[2:])
      deviceType = types.get(str(device.get('device_type')))
      deviceRole = roles.get(str(device.get('device_role')))
      devicePlatform = platforms.get(str(device.get('platform')))
      if not deviceRole:
        deviceRole = roles.get(str(device.get('role')))
      icingaObject = [{}]
      icingaObject = filter(lambda o : o['name'] == deviceName,icingaHosts)
      icingaRole=[]
      icingaServices=[]
      icingaHardware=[]
      if icingaObject: # if object exists then update
        if icingaObject[0].get('attrs').get('vars'):
          icingaRole = icingaObject[0].get('attrs').get('vars').get('role')
          icingaServices = icingaObject[0].get('attrs').get('vars').get('services')
          icingaHardware = icingaObject[0].get('attrs').get('vars').get('hardware')
          logger.debug('ICINGA ROLE FOR HOST %s ARE %s' % (deviceName,icingaRole))
          logger.debug('ICINGA SERVICES FOR HOST %s ARE %s NETBOX %s' % (deviceName,icingaServices,serviceTags))
        
        # SAFEGUARDS
        if not icingaServices: 
          icingaServices=[]
        if not icingaRole: 
          icingaRole=[]
        if not icingaHardware: 
          icingaHardware=[]

        icingaServices.sort()
        serviceTags.sort()
        icingaHardware.sort()
        serviceTags.sort()
        netboxHardware = [devicePlatform,deviceType]
        netboxHardware.sort()

        if not (icingaServices == serviceTags and icingaHardware == netboxHardware ) : # if services not match then update
          logger.info('UPDATE SERVICES FOR DEVICE %s FROM %s TO %s' % (deviceName,icingaServices,serviceTags))
          r=icinga.objects.update('Host',deviceName,{'attrs' :{'vars': {'services': serviceTags, 'hardware' : netboxHardware}}}) # update service tags
          checkResult(r)

          ''' WORKAROUND '''
          r=icinga.objects.delete('Host',deviceName)
          checkResult(r)
          ipID = device.get('primary_ip4')
          ip = nb.ipam.ip_addresses.get(ipID).serialize()
          address = ip.get('address').split('/')[0]
          r = icinga.objects.create('Host',deviceName,['generic-host'],{'address': address, 'vars': {'role' : [deviceRole], 'services': serviceTags, 'hardware' : [devicePlatform,deviceType]}})
          checkResult(r)
          logger.info('CREATED DEVICE %s ADDRESS %s ROLE %s SERVICES %s' % (deviceName,address,deviceRole,serviceTags))
          '''END WORKAROUND '''

        if deviceRole not in icingaRole : # if role is missing
          logger.info('UPDATE ROLE FOR DEVICE %s NETBOX ROLE %s SERVICES %s ICINGA ROLE %s SERVICES %s' % (deviceName,deviceRole,serviceTags,icingaRole,icingaServices))
          
          r=icinga.objects.update('Host',deviceName,{'attrs' :{'vars': {'role' : [deviceRole]}}}) # update role
          checkResult(r)

          ''' WORKAROUND '''
          r=icinga.objects.delete('Host',deviceName)
          checkResult(r)
          ipID = device.get('primary_ip4')
          ip = nb.ipam.ip_addresses.get(ipID).serialize()
          address = ip.get('address').split('/')[0]
          r = icinga.objects.create('Host',deviceName,['generic-host'],{'address': address, 'vars': {'role' : [deviceRole], 'services': serviceTags, 'hardware' : [devicePlatform,deviceType]}})
          checkResult(r)
          logger.info('CREATED DEVICE %s ADDRESS %s ROLE %s SERVICES %s' % (deviceName,address,deviceRole,serviceTags))
          ''' END WORKAROUND '''
          
        else:
          logger.debug('ROLES MATCH - NO CHANGE FOR DEVICE %s' % (deviceName,))
     
      else: # create device
          ipID = device.get('primary_ip4')
          ip = nb.ipam.ip_addresses.get(ipID).serialize()
          address = ip.get('address').split('/')[0]
          r = icinga.objects.create('Host',deviceName,['generic-host'],{'address': address, 'vars': {'role' : [deviceRole], 'services': serviceTags, 'hardware' : [devicePlatform,deviceType]}})
          checkResult(r)
          logger.info('CREATED DEVICE %s ADDRESS %s ROLE %s SERVICES %s' % (deviceName,address,deviceRole,serviceTags))

logger.info("FINISHED NETBOX TO ICINGA DEVICES CHECK" )

# REMOVE DEVICES MISSING #monitor TAG IN NETBOX

logger.info('STARTING ICINGA CLEANUP')
for icingaDevice in icingaHosts:
  icingaName = icingaDevice.get('name')
  if not icingaName == 'icinga':
    netboxDevice = filter(lambda o : o.serialize().get('name') == icingaName,netboxDevices)
    if netboxDevice:
      if not 'monitor' in netboxDevice[0].serialize().get('tags'):
        icinga.objects.delete('Host',icingaName)
        logger.info('REMOVED DEVICE %s' % (icingaName))
    else:
      icinga.objects.delete('Host',icingaName)
      logger.info('REMOVED DEVICE %s' % (icingaName))
logger.info('FINISHED ICINGA CLEANUP')

logger.info('########## DONE IN %ss ##########' % (str(round(time.time()-start,1))))
