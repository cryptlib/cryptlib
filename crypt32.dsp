# Microsoft Developer Studio Project File - Name="Crypt32" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=Crypt32 - Win32 Fuzz
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "crypt32.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "crypt32.mak" CFG="Crypt32 - Win32 Fuzz"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "Crypt32 - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "Crypt32 - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "Crypt32 - Win32 Crosscompile" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "Crypt32 - Win32 Fuzz" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "Crypt32 - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir ".\Release"
# PROP BASE Intermediate_Dir ".\Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir ".\binaries32_vc6"
# PROP Intermediate_Dir ".\release32_vc6"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
F90=fl32.exe
# ADD BASE F90 /I "Release/"
# ADD F90 /I "Release/"
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /c
# ADD CPP /nologo /MD /W3 /O2 /I ".\\" /D "NDEBUG" /FD /c
# SUBTRACT CPP /YX
# ADD BASE MTL /nologo /D "NDEBUG" /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /machine:I386
# ADD LINK32 kernel32.lib user32.lib advapi32.lib netapi32.lib ws2_32.lib /nologo /subsystem:windows /dll /pdb:none /machine:I386 /out:".\binaries32_vc6/cl32.dll"

!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir ".\Debug"
# PROP BASE Intermediate_Dir ".\Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir ".\binaries32_vc6"
# PROP Intermediate_Dir ".\debug32_vc6"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
F90=fl32.exe
# ADD BASE F90 /I "Debug/"
# ADD F90 /I "Debug/"
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /c
# ADD CPP /nologo /MD /W4 /Gm /Zi /Od /I ".\\" /D "CONFIG_FAULTS" /D "CONFIG_DIRECT_API" /D CONFIG_PKC_ALLOCSIZE=256 /Fr /FD /c
# SUBTRACT CPP /YX /Yc /Yu
# ADD BASE MTL /nologo /D "_DEBUG" /win32
# ADD MTL /nologo /D "_DEBUG" /win32
# SUBTRACT MTL /mktyplib203
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /debug /machine:I386
# ADD LINK32 kernel32.lib user32.lib advapi32.lib netapi32.lib ws2_32.lib /nologo /subsystem:windows /dll /pdb:none /debug /machine:I386 /out:".\binaries32_vc6/cl32.dll"
# SUBTRACT LINK32 /map

!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Crosscompile"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Crypt32___Win32_Crosscompile"
# PROP BASE Intermediate_Dir "Crypt32___Win32_Crosscompile"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "binaries_crosscompile"
# PROP Intermediate_Dir "binaries_crosscompile"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
F90=fl32.exe
# ADD BASE F90 /I "Debug/"
# ADD F90 /I "Debug/"
# ADD BASE CPP /nologo /MD /W4 /Gm /Zi /Od /I ".\\" /D "NO_ASM" /FD /c
# SUBTRACT BASE CPP /Fr /YX
# ADD CPP /nologo /MD /W4 /Gm /Zi /Od /I "./" /I "./embedded/vxworks/" /I "./embedded/vxworks/wrn/coreip/" /D "CROSSCOMPILE" /D "CONFIG_RANDSEED" /FD /c
# SUBTRACT CPP /Fr /YX
# ADD BASE MTL /nologo /D "_DEBUG" /win32
# SUBTRACT BASE MTL /mktyplib203
# ADD MTL /nologo /D "_DEBUG" /win32
# SUBTRACT MTL /mktyplib203
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib advapi32.lib /nologo /subsystem:windows /dll /pdb:none /debug /machine:I386 /out:".\binaries32_vc6/cl32.dll"
# ADD LINK32 kernel32.lib user32.lib advapi32.lib /nologo /subsystem:windows /dll /pdb:none /debug /machine:I386 /out:".\binaries32_vc6/cl32.dll"

!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Fuzz"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Crypt32___Win32_Fuzz"
# PROP BASE Intermediate_Dir "Crypt32___Win32_Fuzz"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir ".\binaries32_vc6"
# PROP Intermediate_Dir ".\binaries32_fuzz"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
F90=fl32.exe
# ADD BASE F90 /I "Debug/"
# ADD F90 /I "Debug/"
# ADD BASE CPP /nologo /MD /W4 /Gm /Zi /Od /I ".\\" /FD /c
# SUBTRACT BASE CPP /Fr /YX /Yc /Yu
# ADD CPP /nologo /MD /W4 /Gm /Zi /Od /I ".\\" /D "CONFIG_FUZZ" /FD /c
# SUBTRACT CPP /Fr /YX /Yc /Yu
# ADD BASE MTL /nologo /D "_DEBUG" /win32
# SUBTRACT BASE MTL /mktyplib203
# ADD MTL /nologo /D "_DEBUG" /win32
# SUBTRACT MTL /mktyplib203
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib advapi32.lib netapi32.lib /nologo /subsystem:windows /dll /pdb:none /debug /machine:I386 /out:".\binaries32_vc6/cl32.dll"
# ADD LINK32 kernel32.lib user32.lib advapi32.lib netapi32.lib ws2_32.lib /nologo /subsystem:windows /dll /incremental:no /debug /machine:I386 /out:".\binaries32_vc6/cl32.dll"
# SUBTRACT LINK32 /profile

!ENDIF 

# Begin Target

# Name "Crypt32 - Win32 Release"
# Name "Crypt32 - Win32 Debug"
# Name "Crypt32 - Win32 Crosscompile"
# Name "Crypt32 - Win32 Fuzz"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;hpj;bat;for;f90"
# Begin Group "Bignum library"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\bn\bn_asm.c
# End Source File
# Begin Source File

SOURCE=.\bn\bn_bpsw.c
# End Source File
# Begin Source File

SOURCE=.\bn\bn_exp.c
# End Source File
# Begin Source File

SOURCE=.\bn\bn_exp2.c
# End Source File
# Begin Source File

SOURCE=.\bn\bn_gcd.c
# End Source File
# Begin Source File

SOURCE=.\bn\bn_mul.c
# End Source File
# Begin Source File

SOURCE=.\bn\bn_recp.c
# End Source File
# Begin Source File

SOURCE=.\bn\ec_lib.c
# End Source File
# Begin Source File

SOURCE=.\bn\ec_mult.c
# End Source File
# Begin Source File

SOURCE=.\bn\ecp_mont.c
# End Source File
# Begin Source File

SOURCE=.\bn\ecp_smpl.c
# End Source File
# End Group
# Begin Group "Certificates"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\cert\certrev.c
# End Source File
# Begin Source File

SOURCE=.\cert\certschk.c
# End Source File
# Begin Source File

SOURCE=.\cert\certsign.c
# End Source File
# Begin Source File

SOURCE=.\cert\certval.c
# End Source File
# Begin Source File

SOURCE=.\cert\chain.c
# End Source File
# Begin Source File

SOURCE=.\cert\chk_cert.c
# End Source File
# Begin Source File

SOURCE=.\cert\chk_chain.c
# End Source File
# Begin Source File

SOURCE=.\cert\chk_san.c
# End Source File
# Begin Source File

SOURCE=.\cert\chk_use.c
# End Source File
# Begin Source File

SOURCE=.\cert\comp_cert.c
# End Source File
# Begin Source File

SOURCE=.\cert\comp_curs.c
# End Source File
# Begin Source File

SOURCE=.\cert\comp_del.c
# End Source File
# Begin Source File

SOURCE=.\cert\comp_get.c
# End Source File
# Begin Source File

SOURCE=.\cert\comp_gets.c
# End Source File
# Begin Source File

SOURCE=.\cert\comp_pkiuser.c
# End Source File
# Begin Source File

SOURCE=.\cert\comp_set.c
# End Source File
# Begin Source File

SOURCE=.\cert\dn.c
# End Source File
# Begin Source File

SOURCE=.\cert\dn_rw.c
# End Source File
# Begin Source File

SOURCE=.\cert\dn_rws.c
# End Source File
# Begin Source File

SOURCE=.\cert\dn_string.c
# End Source File
# Begin Source File

SOURCE=.\cert\ext.c
# End Source File
# Begin Source File

SOURCE=.\cert\ext_add.c
# End Source File
# Begin Source File

SOURCE=.\cert\ext_check.c
# End Source File
# Begin Source File

SOURCE=.\cert\ext_copy.c
# End Source File
# Begin Source File

SOURCE=.\cert\ext_def.c
# End Source File
# Begin Source File

SOURCE=.\cert\ext_rd.c
# End Source File
# Begin Source File

SOURCE=.\cert\ext_rdattr.c
# End Source File
# Begin Source File

SOURCE=.\cert\ext_rdstack.c
# End Source File
# Begin Source File

SOURCE=.\cert\ext_wr.c
# End Source File
# Begin Source File

SOURCE=.\cert\imp_check.c
# End Source File
# Begin Source File

SOURCE=.\cert\imp_exp.c
# End Source File
# Begin Source File

SOURCE=.\cert\read.c
# End Source File
# Begin Source File

SOURCE=.\cert\trustmgr.c
# End Source File
# Begin Source File

SOURCE=.\cert\write.c
# End Source File
# Begin Source File

SOURCE=.\cert\write_pre.c
# End Source File
# End Group
# Begin Group "Contexts"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\context\ctx_3des.c
# End Source File
# Begin Source File

SOURCE=.\context\ctx_aes.c
# End Source File
# Begin Source File

SOURCE=.\context\ctx_attr.c
# End Source File
# Begin Source File

SOURCE=.\context\ctx_bn.c
# End Source File
# Begin Source File

SOURCE=.\context\ctx_bnmath.c
# End Source File
# Begin Source File

SOURCE=.\context\ctx_bnpkc.c
# End Source File
# Begin Source File

SOURCE=.\context\ctx_bnprime.c
# End Source File
# Begin Source File

SOURCE=.\context\ctx_bnrw.c
# End Source File
# Begin Source File

SOURCE=.\context\ctx_bnsieve.c
# End Source File
# Begin Source File

SOURCE=.\context\ctx_bntest.c
# End Source File
# Begin Source File

SOURCE=.\context\ctx_cast.c
# End Source File
# Begin Source File

SOURCE=.\context\ctx_chacha20.c
# End Source File
# Begin Source File

SOURCE=.\context\ctx_des.c
# End Source File
# Begin Source File

SOURCE=.\context\ctx_dh.c
# End Source File
# Begin Source File

SOURCE=.\context\ctx_dsa.c
# End Source File
# Begin Source File

SOURCE=.\context\ctx_ecdh.c
# End Source File
# Begin Source File

SOURCE=.\context\ctx_ecdsa.c
# End Source File
# Begin Source File

SOURCE=.\context\ctx_elg.c
# End Source File
# Begin Source File

SOURCE=.\context\ctx_encr.c
# End Source File
# Begin Source File

SOURCE=.\context\ctx_generic.c
# End Source File
# Begin Source File

SOURCE=.\context\ctx_hsha.c
# End Source File
# Begin Source File

SOURCE=.\context\ctx_hsha2.c
# End Source File
# Begin Source File

SOURCE=.\context\ctx_idea.c
# End Source File
# Begin Source File

SOURCE=.\context\ctx_md5.c
# End Source File
# Begin Source File

SOURCE=.\context\ctx_misc.c
# End Source File
# Begin Source File

SOURCE=.\context\ctx_poly1305.c
# End Source File
# Begin Source File

SOURCE=.\context\ctx_rc2.c
# End Source File
# Begin Source File

SOURCE=.\context\ctx_rc4.c
# End Source File
# Begin Source File

SOURCE=.\context\ctx_rsa.c
# End Source File
# Begin Source File

SOURCE=.\context\ctx_sha.c
# End Source File
# Begin Source File

SOURCE=.\context\ctx_sha2.c
# End Source File
# Begin Source File

SOURCE=.\context\key_id.c
# End Source File
# Begin Source File

SOURCE=.\context\key_rdpriv.c
# End Source File
# Begin Source File

SOURCE=.\context\key_rdpub.c
# End Source File
# Begin Source File

SOURCE=.\context\key_wrpriv.c
# End Source File
# Begin Source File

SOURCE=.\context\key_wrpub.c
# End Source File
# Begin Source File

SOURCE=.\context\keyload.c
# End Source File
# Begin Source File

SOURCE=.\context\kg_dlp.c
# End Source File
# Begin Source File

SOURCE=.\context\kg_ecc.c
# End Source File
# Begin Source File

SOURCE=.\context\kg_prime.c
# End Source File
# Begin Source File

SOURCE=.\context\kg_rsa.c
# End Source File
# End Group
# Begin Group "Crypt/Hash algorithms"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\crypt\aes_modes.c
# End Source File
# Begin Source File

SOURCE=.\crypt\aescrypt.c
# End Source File
# Begin Source File

SOURCE=.\crypt\aeskey.c
# End Source File
# Begin Source File

SOURCE=.\crypt\aestab.c
# End Source File
# Begin Source File

SOURCE=.\crypt\castecb.c
# End Source File
# Begin Source File

SOURCE=.\crypt\castenc.c
# End Source File
# Begin Source File

SOURCE=.\crypt\castskey.c
# End Source File
# Begin Source File

SOURCE=.\crypt\chacha20.c
# End Source File
# Begin Source File

SOURCE=.\crypt\descbc.c
# End Source File
# Begin Source File

SOURCE=.\crypt\desecb.c
# End Source File
# Begin Source File

SOURCE=.\crypt\desecb3.c
# End Source File
# Begin Source File

SOURCE=.\crypt\desenc.c
# End Source File
# Begin Source File

SOURCE=.\crypt\desskey.c
# End Source File
# Begin Source File

SOURCE=.\crypt\gcm.c
# End Source File
# Begin Source File

SOURCE=.\crypt\gf128mul.c
# End Source File
# Begin Source File

SOURCE=.\crypt\icbc.c
# End Source File
# Begin Source File

SOURCE=.\crypt\iecb.c
# End Source File
# Begin Source File

SOURCE=.\crypt\iskey.c
# End Source File
# Begin Source File

SOURCE=.\crypt\md5dgst.c
# End Source File
# Begin Source File

SOURCE=.\crypt\poly1305.c
# End Source File
# Begin Source File

SOURCE=.\crypt\rc2cbc.c
# End Source File
# Begin Source File

SOURCE=.\crypt\rc2ecb.c
# End Source File
# Begin Source File

SOURCE=.\crypt\rc2skey.c
# End Source File
# Begin Source File

SOURCE=.\crypt\rc4enc.c
# End Source File
# Begin Source File

SOURCE=.\crypt\rc4skey.c
# End Source File
# Begin Source File

SOURCE=.\crypt\sha1dgst.c
# End Source File
# Begin Source File

SOURCE=.\crypt\sha2.c
# End Source File
# Begin Source File

SOURCE=".\crypt\d-win32.obj"

!IF  "$(CFG)" == "Crypt32 - Win32 Release"

!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Debug"

!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Crosscompile"

# PROP BASE Exclude_From_Build 1
# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Fuzz"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\crypt\aescryptx86.obj
# End Source File
# End Group
# Begin Group "Devices"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\device\dev_attr.c
# End Source File
# Begin Source File

SOURCE=.\device\dev_storage.c
# End Source File
# Begin Source File

SOURCE=.\device\hardware.c
# End Source File
# Begin Source File

SOURCE=.\device\hw_misc.c
# End Source File
# Begin Source File

SOURCE=.\device\hw_templalg.c
# End Source File
# Begin Source File

SOURCE=.\device\hw_template.c
# End Source File
# Begin Source File

SOURCE=.\device\ms_capi.c

!IF  "$(CFG)" == "Crypt32 - Win32 Release"

!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Debug"

!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Crosscompile"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Fuzz"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\device\pkcs11.c
# End Source File
# Begin Source File

SOURCE=.\device\pkcs11_init.c
# End Source File
# Begin Source File

SOURCE=.\device\pkcs11_pkc.c
# End Source File
# Begin Source File

SOURCE=.\device\pkcs11_rd.c
# End Source File
# Begin Source File

SOURCE=.\device\pkcs11_wr.c
# End Source File
# Begin Source File

SOURCE=.\device\system.c
# End Source File
# Begin Source File

SOURCE=.\device\tpm.c
# End Source File
# Begin Source File

SOURCE=.\device\tpm_emu.c
# End Source File
# Begin Source File

SOURCE=.\device\tpm_pkc.c
# End Source File
# End Group
# Begin Group "Encode/Decode"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\enc_dec\asn1_algoenc.c
# End Source File
# Begin Source File

SOURCE=.\enc_dec\asn1_algoid.c
# End Source File
# Begin Source File

SOURCE=.\enc_dec\asn1_check.c
# End Source File
# Begin Source File

SOURCE=.\enc_dec\asn1_ext.c
# End Source File
# Begin Source File

SOURCE=.\enc_dec\asn1_oid.c
# End Source File
# Begin Source File

SOURCE=.\enc_dec\asn1_rd.c
# End Source File
# Begin Source File

SOURCE=.\enc_dec\asn1_wr.c
# End Source File
# Begin Source File

SOURCE=.\enc_dec\base32.c
# End Source File
# Begin Source File

SOURCE=.\enc_dec\base64.c
# End Source File
# Begin Source File

SOURCE=.\enc_dec\base64_id.c
# End Source File
# Begin Source File

SOURCE=.\enc_dec\misc_rw.c
# End Source File
# Begin Source File

SOURCE=.\enc_dec\pgp_rw.c
# End Source File
# End Group
# Begin Group "Envelopes"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\envelope\cms_deenv.c
# End Source File
# Begin Source File

SOURCE=.\envelope\cms_env.c
# End Source File
# Begin Source File

SOURCE=.\envelope\cms_envpre.c
# End Source File
# Begin Source File

SOURCE=.\envelope\decode.c
# End Source File
# Begin Source File

SOURCE=.\envelope\encode.c
# End Source File
# Begin Source File

SOURCE=.\envelope\env_attr.c
# End Source File
# Begin Source File

SOURCE=.\envelope\pgp_deenv.c
# End Source File
# Begin Source File

SOURCE=.\envelope\pgp_env.c
# End Source File
# Begin Source File

SOURCE=.\envelope\res_action.c
# End Source File
# Begin Source File

SOURCE=.\envelope\res_deenv.c
# End Source File
# Begin Source File

SOURCE=.\envelope\res_env.c
# End Source File
# End Group
# Begin Group "I/O"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\io\dns.c
# End Source File
# Begin Source File

SOURCE=.\io\dns_srv.c
# End Source File
# Begin Source File

SOURCE=.\io\eap.c
# End Source File
# Begin Source File

SOURCE=.\io\eap_rd.c
# End Source File
# Begin Source File

SOURCE=.\io\eap_wr.c
# End Source File
# Begin Source File

SOURCE=.\io\file.c
# End Source File
# Begin Source File

SOURCE=.\io\http.c
# End Source File
# Begin Source File

SOURCE=.\io\http_parse.c
# End Source File
# Begin Source File

SOURCE=.\io\http_rd.c
# End Source File
# Begin Source File

SOURCE=.\io\http_wr.c
# End Source File
# Begin Source File

SOURCE=.\io\memory.c
# End Source File
# Begin Source File

SOURCE=.\io\net.c
# End Source File
# Begin Source File

SOURCE=.\io\net_proxy.c
# End Source File
# Begin Source File

SOURCE=.\io\net_trans.c
# End Source File
# Begin Source File

SOURCE=.\io\net_url.c
# End Source File
# Begin Source File

SOURCE=.\io\stream.c
# End Source File
# Begin Source File

SOURCE=.\io\tcp.c
# End Source File
# Begin Source File

SOURCE=.\io\tcp_conn.c
# End Source File
# Begin Source File

SOURCE=.\io\tcp_err.c
# End Source File
# Begin Source File

SOURCE=.\io\tcp_rw.c
# End Source File
# End Group
# Begin Group "Kernel"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\kernel\attr_acl.c
# End Source File
# Begin Source File

SOURCE=.\kernel\certmgt_acl.c
# End Source File
# Begin Source File

SOURCE=.\kernel\init.c
# End Source File
# Begin Source File

SOURCE=.\kernel\int_msg.c
# End Source File
# Begin Source File

SOURCE=.\kernel\key_acl.c
# End Source File
# Begin Source File

SOURCE=.\kernel\mech_acl.c
# End Source File
# Begin Source File

SOURCE=.\kernel\msg_acl.c
# End Source File
# Begin Source File

SOURCE=.\kernel\obj_access.c
# End Source File
# Begin Source File

SOURCE=.\kernel\objects.c
# End Source File
# Begin Source File

SOURCE=.\kernel\sec_mem.c
# End Source File
# Begin Source File

SOURCE=.\kernel\selftest.c
# End Source File
# Begin Source File

SOURCE=.\kernel\semaphore.c
# End Source File
# Begin Source File

SOURCE=.\kernel\sendmsg.c
# End Source File
# Begin Source File

SOURCE=.\kernel\storage.c
# End Source File
# End Group
# Begin Group "Keysets"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\keyset\http_keys.c
# End Source File
# Begin Source File

SOURCE=.\keyset\key_attr.c
# End Source File
# Begin Source File

SOURCE=.\keyset\ldap.c

!IF  "$(CFG)" == "Crypt32 - Win32 Release"

!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Debug"

!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Crosscompile"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Fuzz"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\keyset\pgp.c
# End Source File
# Begin Source File

SOURCE=.\keyset\pgp_rd.c
# End Source File
# Begin Source File

SOURCE=.\keyset\pgp_wr.c
# End Source File
# Begin Source File

SOURCE=.\keyset\pkcs12.c
# End Source File
# Begin Source File

SOURCE=.\keyset\pkcs12_rd.c
# End Source File
# Begin Source File

SOURCE=.\keyset\pkcs12_rdobj.c
# End Source File
# Begin Source File

SOURCE=.\keyset\pkcs12_wr.c
# End Source File
# End Group
# Begin Group "Keysets - DBMS"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\keyset\ca_add.c
# End Source File
# Begin Source File

SOURCE=.\keyset\ca_clean.c
# End Source File
# Begin Source File

SOURCE=.\keyset\ca_issue.c
# End Source File
# Begin Source File

SOURCE=.\keyset\ca_misc.c
# End Source File
# Begin Source File

SOURCE=.\keyset\ca_rev.c
# End Source File
# Begin Source File

SOURCE=.\keyset\dbms.c
# End Source File
# Begin Source File

SOURCE=.\keyset\dbx_misc.c
# End Source File
# Begin Source File

SOURCE=.\keyset\dbx_rd.c
# End Source File
# Begin Source File

SOURCE=.\keyset\dbx_wr.c
# End Source File
# Begin Source File

SOURCE=.\keyset\odbc.c
# End Source File
# End Group
# Begin Group "Keysets - PKCS15"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\keyset\pkcs15.c
# End Source File
# Begin Source File

SOURCE=.\keyset\pkcs15_add.c
# End Source File
# Begin Source File

SOURCE=.\keyset\pkcs15_addpriv.c
# End Source File
# Begin Source File

SOURCE=.\keyset\pkcs15_addpub.c
# End Source File
# Begin Source File

SOURCE=.\keyset\pkcs15_attrrd.c
# End Source File
# Begin Source File

SOURCE=.\keyset\pkcs15_attrwr.c
# End Source File
# Begin Source File

SOURCE=.\keyset\pkcs15_get.c
# End Source File
# Begin Source File

SOURCE=.\keyset\pkcs15_getpkc.c
# End Source File
# Begin Source File

SOURCE=.\keyset\pkcs15_rd.c
# End Source File
# Begin Source File

SOURCE=.\keyset\pkcs15_set.c
# End Source File
# Begin Source File

SOURCE=.\keyset\pkcs15_wr.c
# End Source File
# End Group
# Begin Group "Mechanisms"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\mechs\keyex.c
# End Source File
# Begin Source File

SOURCE=.\mechs\keyex_int.c
# End Source File
# Begin Source File

SOURCE=.\mechs\keyex_rw.c
# End Source File
# Begin Source File

SOURCE=.\mechs\mech_cwrap.c
# End Source File
# Begin Source File

SOURCE=.\mechs\mech_derive.c
# End Source File
# Begin Source File

SOURCE=.\mechs\mech_int.c
# End Source File
# Begin Source File

SOURCE=.\mechs\mech_pkwrap.c
# End Source File
# Begin Source File

SOURCE=.\mechs\mech_privk.c
# End Source File
# Begin Source File

SOURCE=.\mechs\mech_sign.c
# End Source File
# Begin Source File

SOURCE=.\mechs\obj_query.c
# End Source File
# Begin Source File

SOURCE=.\mechs\sign.c
# End Source File
# Begin Source File

SOURCE=.\mechs\sign_cms.c
# End Source File
# Begin Source File

SOURCE=.\mechs\sign_int.c
# End Source File
# Begin Source File

SOURCE=.\mechs\sign_pgp.c
# End Source File
# Begin Source File

SOURCE=.\mechs\sign_rw.c
# End Source File
# Begin Source File

SOURCE=.\mechs\sign_x509.c
# End Source File
# End Group
# Begin Group "Misc"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\crypt32.def
# End Source File
# Begin Source File

SOURCE=.\crypt32.rc
# End Source File
# Begin Source File

SOURCE=.\misc\int_api.c
# End Source File
# Begin Source File

SOURCE=.\misc\int_attr.c
# End Source File
# Begin Source File

SOURCE=.\misc\int_debug.c
# End Source File
# Begin Source File

SOURCE=.\misc\int_env.c
# End Source File
# Begin Source File

SOURCE=.\misc\int_err.c
# End Source File
# Begin Source File

SOURCE=.\misc\int_mem.c
# End Source File
# Begin Source File

SOURCE=.\misc\int_string.c
# End Source File
# Begin Source File

SOURCE=.\misc\int_time.c
# End Source File
# Begin Source File

SOURCE=.\bindings\java_jni.c
# End Source File
# Begin Source File

SOURCE=.\misc\os_spec.c
# End Source File
# Begin Source File

SOURCE=.\misc\pgp_misc.c
# End Source File
# Begin Source File

SOURCE=.\random\rand_x917.c
# End Source File
# Begin Source File

SOURCE=.\random\random.c
# End Source File
# Begin Source File

SOURCE=.\misc\user.c
# End Source File
# Begin Source File

SOURCE=.\misc\user_attr.c
# End Source File
# Begin Source File

SOURCE=.\misc\user_config.c
# End Source File
# Begin Source File

SOURCE=.\misc\user_rw.c
# End Source File
# Begin Source File

SOURCE=.\random\win32.c

!IF  "$(CFG)" == "Crypt32 - Win32 Release"

!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Debug"

!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Crosscompile"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Fuzz"

!ENDIF 

# End Source File
# End Group
# Begin Group "Sessions"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\session\scorebrd.c
# End Source File
# Begin Source File

SOURCE=.\session\sess_attr.c
# End Source File
# Begin Source File

SOURCE=.\session\sess_iattr.c
# End Source File
# Begin Source File

SOURCE=.\session\sess_rd.c
# End Source File
# Begin Source File

SOURCE=.\session\sess_websock.c
# End Source File
# Begin Source File

SOURCE=.\session\sess_wr.c
# End Source File
# Begin Source File

SOURCE=.\session\session.c
# End Source File
# End Group
# Begin Group "Sessions - SSH"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\session\ssh.c
# End Source File
# Begin Source File

SOURCE=.\session\ssh2.c
# End Source File
# Begin Source File

SOURCE=.\session\ssh2_algo.c
# End Source File
# Begin Source File

SOURCE=.\session\ssh2_authcli.c
# End Source File
# Begin Source File

SOURCE=.\session\ssh2_authsvr.c
# End Source File
# Begin Source File

SOURCE=.\session\ssh2_channel.c
# End Source File
# Begin Source File

SOURCE=.\session\ssh2_cli.c
# End Source File
# Begin Source File

SOURCE=.\session\ssh2_crypt.c
# End Source File
# Begin Source File

SOURCE=.\session\ssh2_id.c
# End Source File
# Begin Source File

SOURCE=.\session\ssh2_msg.c
# End Source File
# Begin Source File

SOURCE=.\session\ssh2_msgcli.c
# End Source File
# Begin Source File

SOURCE=.\session\ssh2_msgsvr.c
# End Source File
# Begin Source File

SOURCE=.\session\ssh2_rd.c
# End Source File
# Begin Source File

SOURCE=.\session\ssh2_svr.c
# End Source File
# Begin Source File

SOURCE=.\session\ssh2_wr.c
# End Source File
# End Group
# Begin Group "Sessions - TLS"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\session\tls.c
# End Source File
# Begin Source File

SOURCE=.\session\tls13_crypt.c
# End Source File
# Begin Source File

SOURCE=.\session\tls13_hs.c
# End Source File
# Begin Source File

SOURCE=.\session\tls13_keyex.c
# End Source File
# Begin Source File

SOURCE=.\session\tls_cert.c
# End Source File
# Begin Source File

SOURCE=.\session\tls_cli.c
# End Source File
# Begin Source File

SOURCE=.\session\tls_crypt.c
# End Source File
# Begin Source File

SOURCE=.\session\tls_ext.c
# End Source File
# Begin Source File

SOURCE=.\session\tls_ext_rw.c
# End Source File
# Begin Source File

SOURCE=.\session\tls_hello.c
# End Source File
# Begin Source File

SOURCE=.\session\tls_hscomplete.c
# End Source File
# Begin Source File

SOURCE=.\session\tls_keymgt.c
# End Source File
# Begin Source File

SOURCE=.\session\tls_rd.c
# End Source File
# Begin Source File

SOURCE=.\session\tls_sign.c
# End Source File
# Begin Source File

SOURCE=.\session\tls_suites.c
# End Source File
# Begin Source File

SOURCE=.\session\tls_svr.c
# End Source File
# Begin Source File

SOURCE=.\session\tls_wr.c
# End Source File
# End Group
# Begin Group "Sessions - PKI"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\session\certstore.c
# End Source File
# Begin Source File

SOURCE=.\session\cmp.c
# End Source File
# Begin Source File

SOURCE=.\session\cmp_cli.c
# End Source File
# Begin Source File

SOURCE=.\session\cmp_crypt.c
# End Source File
# Begin Source File

SOURCE=.\session\cmp_err.c
# End Source File
# Begin Source File

SOURCE=.\session\cmp_rd.c
# End Source File
# Begin Source File

SOURCE=.\session\cmp_rdmsg.c
# End Source File
# Begin Source File

SOURCE=.\session\cmp_svr.c
# End Source File
# Begin Source File

SOURCE=.\session\cmp_wr.c
# End Source File
# Begin Source File

SOURCE=.\session\cmp_wrmsg.c
# End Source File
# Begin Source File

SOURCE=.\session\ocsp.c
# End Source File
# Begin Source File

SOURCE=.\session\pnppki.c
# End Source File
# Begin Source File

SOURCE=.\session\rtcs.c
# End Source File
# Begin Source File

SOURCE=.\session\scep.c
# End Source File
# Begin Source File

SOURCE=.\session\scep_cli.c
# End Source File
# Begin Source File

SOURCE=.\session\scep_svr.c
# End Source File
# Begin Source File

SOURCE=.\session\scvp.c
# End Source File
# Begin Source File

SOURCE=.\session\scvp_cli.c
# End Source File
# Begin Source File

SOURCE=.\session\scvp_svr.c
# End Source File
# Begin Source File

SOURCE=.\session\tsp.c
# End Source File
# End Group
# Begin Group "Zlib"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\zlib\adler32.c
# End Source File
# Begin Source File

SOURCE=.\zlib\deflate.c
# End Source File
# Begin Source File

SOURCE=.\zlib\inffast.c
# End Source File
# Begin Source File

SOURCE=.\zlib\inflate.c
# End Source File
# Begin Source File

SOURCE=.\zlib\inftrees.c
# End Source File
# Begin Source File

SOURCE=.\zlib\trees.c
# End Source File
# Begin Source File

SOURCE=.\zlib\zutil.c
# End Source File
# End Group
# Begin Source File

SOURCE=.\cryptapi.c

!IF  "$(CFG)" == "Crypt32 - Win32 Release"

!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Debug"

# SUBTRACT CPP /D CONFIG_PKC_ALLOCSIZE=256

!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Crosscompile"

# ADD CPP /I "./embedded/freertos/"

!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Fuzz"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\cryptcrt.c

!IF  "$(CFG)" == "Crypt32 - Win32 Release"

!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Debug"

# SUBTRACT CPP /D CONFIG_PKC_ALLOCSIZE=256

!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Crosscompile"

# ADD CPP /I "./embedded/freertos/"

!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Fuzz"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\cryptctx.c

!IF  "$(CFG)" == "Crypt32 - Win32 Release"

!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Debug"

# SUBTRACT CPP /D CONFIG_PKC_ALLOCSIZE=256

!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Crosscompile"

# ADD CPP /I "./embedded/freertos/"

!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Fuzz"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\cryptdev.c

!IF  "$(CFG)" == "Crypt32 - Win32 Release"

!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Debug"

# SUBTRACT CPP /D CONFIG_PKC_ALLOCSIZE=256

!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Crosscompile"

# ADD CPP /I "./embedded/freertos/"

!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Fuzz"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\cryptenv.c

!IF  "$(CFG)" == "Crypt32 - Win32 Release"

!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Debug"

# SUBTRACT CPP /D CONFIG_PKC_ALLOCSIZE=256

!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Crosscompile"

# ADD CPP /I "./embedded/freertos/"

!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Fuzz"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\cryptkey.c

!IF  "$(CFG)" == "Crypt32 - Win32 Release"

!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Debug"

# SUBTRACT CPP /D CONFIG_PKC_ALLOCSIZE=256

!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Crosscompile"

# ADD CPP /I "./embedded/freertos/"

!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Fuzz"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\cryptlib.c

!IF  "$(CFG)" == "Crypt32 - Win32 Release"

!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Debug"

# SUBTRACT CPP /D CONFIG_PKC_ALLOCSIZE=256

!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Crosscompile"

# ADD CPP /I "./embedded/freertos/"

!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Fuzz"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\cryptses.c

!IF  "$(CFG)" == "Crypt32 - Win32 Release"

!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Debug"

# SUBTRACT CPP /D CONFIG_PKC_ALLOCSIZE=256

!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Crosscompile"

# ADD CPP /I "./embedded/freertos/"

!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Fuzz"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\cryptusr.c

!IF  "$(CFG)" == "Crypt32 - Win32 Release"

!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Debug"

# SUBTRACT CPP /D CONFIG_PKC_ALLOCSIZE=256

!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Crosscompile"

# ADD CPP /I "./embedded/freertos/"

!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Fuzz"

!ENDIF 

# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl;fi;fd"
# Begin Group "Certificates - Headers"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\cert\cert.h
# End Source File
# Begin Source File

SOURCE=.\cert\certattr.h
# End Source File
# Begin Source File

SOURCE=.\cert\certfn.h
# End Source File
# Begin Source File

SOURCE=.\cert\dn.h
# End Source File
# Begin Source File

SOURCE=.\cert\trustmgr.h
# End Source File
# Begin Source File

SOURCE=.\cert\trustmgr_int.h
# End Source File
# End Group
# Begin Group "Devices - Headers"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\device\capabil.h
# End Source File
# Begin Source File

SOURCE=.\device\device.h
# End Source File
# Begin Source File

SOURCE=.\device\hardware.h
# End Source File
# Begin Source File

SOURCE=.\device\hw_template.h
# End Source File
# Begin Source File

SOURCE=.\device\pkcs11_api.h
# End Source File
# Begin Source File

SOURCE=.\device\tpm.h
# End Source File
# End Group
# Begin Group "Encode/Decode - Headers"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\enc_dec\asn1.h
# End Source File
# Begin Source File

SOURCE=.\enc_dec\asn1_ext.h
# End Source File
# Begin Source File

SOURCE=.\enc_dec\asn1_int.h
# End Source File
# Begin Source File

SOURCE=.\enc_dec\misc_rw.h
# End Source File
# Begin Source File

SOURCE=.\enc_dec\pgp_rw.h
# End Source File
# End Group
# Begin Group "I/O - Headers"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\io\eap.h
# End Source File
# Begin Source File

SOURCE=.\io\file.h
# End Source File
# Begin Source File

SOURCE=.\io\http.h
# End Source File
# Begin Source File

SOURCE=.\io\stream.h
# End Source File
# Begin Source File

SOURCE=.\io\stream_int.h
# End Source File
# Begin Source File

SOURCE=.\io\tcp.h
# End Source File
# Begin Source File

SOURCE=.\io\tcp_int.h
# End Source File
# End Group
# Begin Group "Kernel - Headers"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\kernel\acl.h
# End Source File
# Begin Source File

SOURCE=.\kernel\acl_perm.h
# End Source File
# Begin Source File

SOURCE=.\cryptkrn.h
# End Source File
# Begin Source File

SOURCE=.\kernel\kernel.h
# End Source File
# Begin Source File

SOURCE=.\kernel\kernelfns.h
# End Source File
# Begin Source File

SOURCE=.\kernel\objectfns.h
# End Source File
# Begin Source File

SOURCE=.\kernel\thread.h
# End Source File
# End Group
# Begin Group "Keysets - Headers"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\keyset\dbms.h
# End Source File
# Begin Source File

SOURCE=.\keyset\keyset.h
# End Source File
# Begin Source File

SOURCE=.\keyset\pgp_key.h
# End Source File
# Begin Source File

SOURCE=.\keyset\pkcs12.h
# End Source File
# Begin Source File

SOURCE=.\keyset\pkcs15.h
# End Source File
# End Group
# Begin Group "Misc - Headers"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\misc\analyse.h
# End Source File
# Begin Source File

SOURCE=.\misc\config.h
# End Source File
# Begin Source File

SOURCE=.\misc\consts.h
# End Source File
# Begin Source File

SOURCE=.\misc\debug.h
# End Source File
# Begin Source File

SOURCE=.\misc\fault.h
# End Source File
# Begin Source File

SOURCE=.\misc\int_api.h
# End Source File
# Begin Source File

SOURCE=.\misc\list.h
# End Source File
# Begin Source File

SOURCE=.\misc\os_detect.h
# End Source File
# Begin Source File

SOURCE=.\misc\os_spec.h
# End Source File
# Begin Source File

SOURCE=.\random\random.h
# End Source File
# Begin Source File

SOURCE=.\random\random_int.h
# End Source File
# Begin Source File

SOURCE=.\misc\safety.h
# End Source File
# Begin Source File

SOURCE=.\misc\user.h
# End Source File
# Begin Source File

SOURCE=.\misc\user_int.h
# End Source File
# End Group
# Begin Group "Sessions - Headers"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\session\certstore.h
# End Source File
# Begin Source File

SOURCE=.\session\cmp.h
# End Source File
# Begin Source File

SOURCE=.\session\scep.h
# End Source File
# Begin Source File

SOURCE=.\session\scorebrd.h
# End Source File
# Begin Source File

SOURCE=.\session\scorebrd_int.h
# End Source File
# Begin Source File

SOURCE=.\session\scvp.h
# End Source File
# Begin Source File

SOURCE=.\session\session.h
# End Source File
# Begin Source File

SOURCE=.\session\ssh.h
# End Source File
# Begin Source File

SOURCE=.\session\tls.h
# End Source File
# Begin Source File

SOURCE=.\session\tls_ext.h
# End Source File
# Begin Source File

SOURCE=.\session\websockets.h
# End Source File
# End Group
# Begin Group "Mechanisms - Headers"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\mechs\dev_mech.h
# End Source File
# Begin Source File

SOURCE=.\mechs\mech.h
# End Source File
# Begin Source File

SOURCE=.\mechs\mech_int.h
# End Source File
# End Group
# Begin Group "Crypt - Headers"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\crypt\aes.h
# End Source File
# Begin Source File

SOURCE=.\crypt\aes_ni.h
# End Source File
# Begin Source File

SOURCE=.\crypt\aesopt.h
# End Source File
# Begin Source File

SOURCE=.\crypt\aestab.h
# End Source File
# Begin Source File

SOURCE=.\bn\bn.h
# End Source File
# Begin Source File

SOURCE=.\bn\bn_lcl.h
# End Source File
# Begin Source File

SOURCE=.\bn\bn_orig.h
# End Source File
# Begin Source File

SOURCE=.\crypt\brg_endian.h
# End Source File
# Begin Source File

SOURCE=.\crypt\brg_types.h
# End Source File
# Begin Source File

SOURCE=.\crypt\djb.h
# End Source File
# Begin Source File

SOURCE=.\bn\ec.h
# End Source File
# Begin Source File

SOURCE=.\bn\ec_lcl.h
# End Source File
# Begin Source File

SOURCE=.\crypt\gcm.h
# End Source File
# Begin Source File

SOURCE=.\crypt\mode_hdr.h
# End Source File
# Begin Source File

SOURCE=.\crypt\osconfig.h
# End Source File
# Begin Source File

SOURCE=.\crypt\sha2.h
# End Source File
# End Group
# Begin Source File

SOURCE=.\context\context.h
# End Source File
# Begin Source File

SOURCE=.\crypt.h
# End Source File
# Begin Source File

SOURCE=.\cryptlib.h
# End Source File
# Begin Source File

SOURCE=.\envelope\envelope.h
# End Source File
# Begin Source File

SOURCE=.\misc\pgp.h
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;cnt;rtf;gif;jpg;jpeg;jpe"
# Begin Source File

SOURCE=.\crypt32.ico
# End Source File
# End Group
# End Target
# End Project
