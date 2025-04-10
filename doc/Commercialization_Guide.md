# Commercialization Guide for IoT device with SmartThings SDK

Please contact partners@smartthings.com for commercialization inquiries.

### Check List for the commercialization
1. Products shall have unique serial number and public key.<br/>
We recommend to modify and apply the opensource example tools in the link below to suit each company's production.

- [STDK key generation tool](https://github.com/SmartThingsCommunity/st-device-sdk-c/blob/main/doc/STDK_Key_Generation.md)
- [STDK QR generation tool](https://github.com/SmartThingsCommunity/st-device-sdk-c/blob/main/doc/STDK_QR_Generation.md)

2. Created serial number, public key and private key shall be saved in the secure module.<br/>
Private key shall not be exposed to the outside and shall be injected and stored in the secure region of the device.

3. Serial Number and Device Public key shall be registered with Samsung SmartThings before sale.

4. QR should be attached to the device for the commercialization.
- The QR size requested for the product should meet the specifications below.
  - Recommended : Above 10mm * 10mm
  - Minimum : 7mm * 7mm

5. Products certified by WWST shall have a WWST logo attached to the product package.<br/>  You can get the WWST(Work With Samsung SmartThings) Logo image with [the following link](https://partners.smartthings.com/brand-guidelines).

6. Products shall provide the firmware update function for security patch, feature upgrade, bug fix and etc.<br/>
If the partner has their own firmware update system, they can use it.<br/> But if not, they can implement it by referring to [the OTA guide](https://github.com/SmartThingsCommunity/st-device-sdk-c-ref/blob/main/doc/ota_demo.md) we provide.