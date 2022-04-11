---
title: "Lack of rechecking permissions in Android"
date: "2017-04-11"
categories: 
  - "android"
  - "pentest"
tags: 
  - "android-permissions"
  - "change-adndroid-permission"
  - "packages-xml"
coverImage: "android-package-1-1-1024x608.png"
---

Yesterday me and one of my friends were working on an Android Penetration testing project. After testing some kinds of exploit then we somehow get root privilege with some kinds of limitations. In the case of this exploit we can just write to any file we want and we cannot do anything more because ASLR was preventing us to do.

So we just think how we could do something to violate privacy of this Android device then as we know previously, Android devices has some kinds of files that save applications signatures and package names and permissions and this file is placed in :

/data/system/packages.xml

Another juicy file which holds what kinds of groups has access to what kinds of devices is also available in :

/etc/permissions/platform.xml

Then we start to edit the first file to see if it is possible to change the permissions of an special package or not, so we do like this :

![](../../assets/images/android-package-1-1-1024x608.png)

And then find something like this :

![](../../assets/images/android-package-2-1024x298.png)

But in the real case we just edit our application's permissions and add another permissions to it, then restart the phone and then opened our previous application but this time with new permissions ! Unfortunately it works and has access to this new permissions and I wonder how google didn’t check permissions again ?! They store lots of signatures and use a huge number of cryptography algorithms to check integrity of files but doesn’t recheck this important stuffs. It also works on /etc/permissions/platform.xml, this file has the same affect somehow but it is not as important as previous file because this is some kind of OS settings file but packages.xml holds settings for every applications.

Note : we test this commands in Android 5.1.0 but I think google has no plan or doesn’t have any plan to add a new approach for checking permissions validation on newer versions of Android so it should work on newer versions too but not tested.

The need to check permissions again is theoretically needless because no one can access to edit this files but I think it should be done by google because in the case of exploits it can have bad affects in people's privacy.

That’s it guys.
