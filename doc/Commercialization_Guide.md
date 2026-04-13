# Commercialization Guide for IoT Devices with the SmartThings SDK

Please contact partners@smartthings.com for commercialization inquiries.

### Checklist for Commercialization
1. Products shall have a unique serial number and a public key.<br/>
We recommend modifying and applying the open-source example tools in the link below to suit each company's production.

- [STDK key generation tool](https://github.com/SmartThingsCommunity/st-device-sdk-c/blob/main/doc/STDK_Key_Generation.md)
- [STDK QR generation tool](https://github.com/SmartThingsCommunity/st-device-sdk-c/blob/main/doc/STDK_QR_Generation.md)

2. The created serial number, public key, and private key shall be saved in a secure module.<br/>
The private key shall not be exposed to the outside and shall be injected and stored in the secure region of the device.

3. The Serial Number and the Device Public Key shall be registered with Samsung SmartThings before sale.

4. A QR code should be attached to the device for commercialization.
- The QR code size requested for the product should meet the specifications below.
  - Recommended: 10mm x 10mm or larger
  - Minimum: 7mm x 7mm

5. Products certified by WWST shall have a WWST logo attached to the product package.<br/>  You can get the WWST (Work With Samsung SmartThings) logo image at [the following link](https://partners.smartthings.com/brand-guidelines).

6. Products shall provide the firmware update function for security patches, feature upgrades, bug fixes, and other updates.<br/>
If the partner has their own firmware update system, they can use it.<br/> However, if not, they can implement it by referring to the OTA guide we provide at [this link](https://github.com/SmartThingsCommunity/st-device-sdk-c-ref/blob/main/doc/ota_demo.md).

7. Currently, we support a cloud certificate valid until **January 15, 2038**. We will continue to update new certificates in the SDK as the expiry date approaches. However, for your device to operate with the new extended certificate, you need to keep supporting the firmware update service, as the certificate update should be conducted via firmware update. If a device isn't updated with the new certificate, the device will fail to connect to the SmartThings cloud service after the expiry date.

8. There are Attribute update quota limitations for a device. Please be advised that your device must operate within these constraints.

- Attribute update count limit: **50 updates** per minute.
- Attribute update data size limit: **200 MB total** per month.
