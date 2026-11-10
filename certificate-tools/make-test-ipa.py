import pathlib, plistlib, struct, zipfile
root=pathlib.Path(__file__).resolve().parent / 'test-fixture'
root.mkdir(exist_ok=True)
# Non-runnable synthetic ARM64 Mach-O. Only used to exercise signing offline.
def seg(name,addr,size,off,filesize,prot,section=b''):
    return struct.pack('<II16sQQQQIIII',0x19,72+len(section),name.encode(),addr,size,off,filesize,7,prot,1 if section else 0,0)+section
text_section=struct.pack('<16s16sQQIIIIIIII',b'__text',b'__TEXT',0x100000400,8,1024,2,0,0,0x80000400,0,0,0)
commands=seg('__TEXT',0x100000000,0x4000,0,4096,5,text_section)+seg('__LINKEDIT',0x100004000,0x4000,4096,16,1)+struct.pack('<IIQQ',0x80000028,24,1024,0)
data=bytearray(struct.pack('<IIIIIIII',0xfeedfacf,0x100000c,0,2,3,len(commands),0x200085,0)+commands)
data.extend(bytes(4112-len(data)))
data[1024:1032]=bytes.fromhex('000080d2c0035fd6')
info={'CFBundleIdentifier':'com.example.trolldock.test','CFBundleName':'TestFixture','CFBundleExecutable':'TestFixture','CFBundlePackageType':'APPL','CFBundleVersion':'1','CFBundleShortVersionString':'1.0','MinimumOSVersion':'15.0'}
with zipfile.ZipFile(root/'unsigned.ipa','w') as archive:
    archive.writestr('Payload/TestFixture.app/Info.plist',plistlib.dumps(info))
    archive.writestr('Payload/TestFixture.app/TestFixture',data)
    archive.writestr('Payload/TestFixture.app/fixture.txt','Synthetic test only; do not install on a device.')
with zipfile.ZipFile(root/'unsigned.ipa') as original, zipfile.ZipFile(root/'unsigned-extension.ipa','w') as archive:
    for name in original.namelist(): archive.writestr(name, original.read(name))
    extension_info=dict(info, CFBundleIdentifier='com.example.trolldock.test.extension', NSExtension={'NSExtensionPointIdentifier':'com.apple.widgetkit-extension'})
    archive.writestr('Payload/TestFixture.app/PlugIns/Sample.appex/Info.plist',plistlib.dumps(extension_info))
    archive.writestr('Payload/TestFixture.app/PlugIns/Sample.appex/TestFixture',data)
print(root/'unsigned.ipa')
