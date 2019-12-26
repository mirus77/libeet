/* Configure script for xmlsec, specific for Windows with Scripting Host.
 *
 * This script will configure the libxmlsec build process and create necessary files.
 * Run it with an 'help', or an invalid option and it will tell you what options
 * it accepts.
 *
 * March 2002, Igor Zlatkovic <igor@stud.fh-frankfurt.de>
 *	Created for LibXML and LibXSLT
 * April 2002, Aleksey Sanin <aleksey@aleksey.com>
 *	Modified for XMLSec Libary
 * April 2002, Miroslav Kundela <mail@mirus.cz>
 *	Modified for LibEETSigner Libary
 */

/* The source directory, relative to the one where this file resides. */
var baseDir = "..";
var srcDir = baseDir + "\\src";
var srcDirApps = baseDir + "\\apps";
/* The directory where we put the binaries after compilation. */
var binDir = "binaries";
/* Base name of what we are building. */
var baseName = "libEETSigner";
var cruntime = "/MD";

/* Configure file which contains the version and the output file where
   we can store our build configuration. */
var configFile = baseDir + "\\configure.ac";
var versionFile = ".\\configure.txt";

/* Input and output files regarding the lib(e)xml features. The second
   output file is there for the compatibility reasons, otherwise it
   is identical to the first. */
var optsFileIn = baseDir + "\\config.h.in";
var optsFile = baseDir + "\\config.h";

var verFileIn = "version32.rc.in";
var verFile = "version32.rc";

var verhFileIn = baseDir + "\\include\\libeet\\version.h.in";
var verhFile = baseDir + "\\include\\libeet\\version.h";

/* Version strings for the binary distribution. Will be filled later
   in the code. */
var verMajorLibEETSigner;
var verMinorLibEETSigner;
var verMicroLibEETSigner;

/* Win32 build options. */
var buildUnicode = 1;
var buildDebug = 0;
var buildPrefix = ".";
var buildBinPrefix = "$(PREFIX)\\bin";
var buildIncPrefix = "$(PREFIX)\\include";
var buildLibPrefix = "$(PREFIX)\\lib";
var buildSoPrefix = "$(PREFIX)\\lib";
var buildInclude = ".";
var buildLib = ".";
var buildPlatform = "x86";
/* Local stuff */
var error = 0;

/* libeet features. */
var withOpenSSLVersion = "110";
var withIconv = 1;

/* Helper function, transforms the option variable into the 'Enabled'
   or 'Disabled' string. */
function boolToStr(opt)
{
	if (opt == false)
		return "Disabled";
	else if (opt == true)
		return "Enabled";
	error = 1;
	return "Undefined";
}

/* Helper function, transforms the argument string into the boolean
   value. */
function strToBool(opt)
{
	if (opt == "0" || opt == "no")
		return false;
	else if (opt == "1" || opt == "yes")
		return true;
	error = 1;
	return false;
}

/* Displays the details about how to use this script. */
function usage()
{
	var txt;
	txt = "Usage:\n";
	txt += "  cscript " + WScript.ScriptName + " <options>\n";
	txt += "  cscript " + WScript.ScriptName + " help\n\n";
	txt += "Options can be specified in the form <option>=<value>, where the value is\n";
	txt += "either 'yes' or 'no'.\n\n";
	txt += "LibEETSigner Library options, default value given in parentheses:\n\n";
	txt += "\nWin32 build options, default value given in parentheses:\n\n";
	txt += "  unicode:    Build Unicode version (" + (buildUnicode? "yes" : "no")  + ")\n";
	txt += "  iconv:      Use the iconv library (" + (withIconv? "yes" : "no")  + ")\n";
	txt += "  debug:      Build unoptimised debug executables (" + (buildDebug? "yes" : "no")  + ")\n";
	txt += "  prefix:     Base directory for the installation (" + buildPrefix + ")\n";
	txt += "  bindir:     Directory where xmlsec and friends should be installed\n";
	txt += "              (" + buildBinPrefix + ")\n";
	txt += "  incdir:     Directory where headers should be installed\n";
	txt += "              (" + buildIncPrefix + ")\n";
	txt += "  libdir:     Directory where static and import libraries should be\n";
	txt += "              installed (" + buildLibPrefix + ")\n";
	txt += "  sodir:      Directory where shared libraries should be installed\n";
	txt += "              (" + buildSoPrefix + ")\n";
	txt += "  include:    Additional search path for the compiler, particularily\n";
	txt += "              where libxml headers can be found (" + buildInclude + ")\n";
	txt += "  lib:        Additional search path for the linker, particularily\n";
	txt += "              where libxml library can be found (" + buildLib + ")\n";
	txt += "  cruntime:   C-runtime compiler option (only msvc) (" + cruntime + ")\n";
	WScript.Echo(txt);
}

/* Discovers the version we are working with by reading the apropriate
   configuration file. Despite its name, this also writes the configuration
   file included by our makefile. */
function discoverVersion()
{
	var fso, cf, vf, ln, s;

	fso = new ActiveXObject("Scripting.FileSystemObject");
	cf = fso.OpenTextFile(configFile, 1);
	vf = fso.CreateTextFile(versionFile, true);
	vf.WriteLine("# " + versionFile);
	vf.WriteLine("# This file is generated automatically by " + WScript.ScriptName + ".");
	vf.WriteBlankLines(1);
	while (cf.AtEndOfStream != true) {
		ln = cf.ReadLine();
		s = new String(ln);
		if (s.search(/^LIBEET_VERSION_MAJOR/) != -1) {
			WScript.Echo(verMajorLibEETSigner);
			vf.WriteLine(s);
			verMajorLibEETSigner = s.substring(s.indexOf("=") + 1, s.length)
		} else if(s.search(/^LIBEET_VERSION_MINOR/) != -1) {
			vf.WriteLine(s);
			verMinorLibEETSigner = s.substring(s.indexOf("=") + 1, s.length)
		} else if(s.search(/^LIBEET_VERSION_SUBMINOR/) != -1) {
			vf.WriteLine(s);
			verMicroLibEETSigner = s.substring(s.indexOf("=") + 1, s.length)
		}
	}
	cf.Close();
	vf.WriteLine("BASEDIR=" + baseDir);
	vf.WriteLine("LIBEET_SRCDIR=" + srcDir);
	vf.WriteLine("APPS_SRCDIR=" + srcDirApps);
	vf.WriteLine("BINDIR=" + binDir);
	vf.WriteLine("UNICODE=" + (buildUnicode? "1" : "0"));
    vf.WriteLine("WITH_OPENSSL_VERSION=XMLSEC_OPENSSL_" + withOpenSSLVersion);
    vf.WriteLine("WITH_ICONV=" + (withIconv ? "1" : "0"));
	vf.WriteLine("DEBUG=" + (buildDebug? "1" : "0"));
	vf.WriteLine("STATIC=" + (buildStatic? "1" : "0"));
	vf.WriteLine("PREFIX=" + buildPrefix);
	vf.WriteLine("BINPREFIX=" + buildBinPrefix);
	vf.WriteLine("INCPREFIX=" + buildIncPrefix);
	vf.WriteLine("LIBPREFIX=" + buildLibPrefix);
	vf.WriteLine("SOPREFIX=" + buildSoPrefix);
	vf.WriteLine("INCLUDE=$(INCLUDE);" + buildInclude);
	vf.WriteLine("LIB=$(LIB);" + buildLib);
	vf.WriteLine("CRUNTIME=" + cruntime);
	vf.Close();
}

function discoverBuildPlatform()
{
  var objShl, poms;
  objShl = new ActiveXObject("wscript.shell");
  poms = objShl.ExpandEnvironmentStrings("%PLATFORM%");
  if (poms != "%PLATFORM%") {
    buildPlatform = poms;
  }
}

/* Configures xmlsec. This one will generate config.h from config.h.in
   taking what the user passed on the command line into account. */
function configureLibEET()
{
	var fso, ofi, of, ln, s;
	fso = new ActiveXObject("Scripting.FileSystemObject");
	ofi = fso.OpenTextFile(optsFileIn, 1);
	of = fso.CreateTextFile(optsFile, true);
	while (ofi.AtEndOfStream != true) {
		ln = ofi.ReadLine();
		s = new String(ln);
		if (s.search(/\@VERSION\@/) != -1) {
			of.WriteLine(s.replace(/\@VERSION\@/,
				verMajorXmlSec + "." + verMinorXmlSec + "." + verMicroLibEETSigner));
		} else if (s.search(/\@XMLSECVERSION_NUMBER\@/) != -1) {
			of.WriteLine(s.replace(/\@XMLSECVERSION_NUMBER\@/,
				verMajorLibEETSigner*10000 + verMinorLibEETSigner*100 + verMicroLibEETSigner*1));
		} else
			of.WriteLine(ln);
	}
	ofi.Close();
	of.Close();
}

function configureVersion32()
{
	var fso, ofi, of, ln, s;
	fso = new ActiveXObject("Scripting.FileSystemObject");
	ofi = fso.OpenTextFile(verFileIn, 1);
	of = fso.CreateTextFile(verFile, true);
	while (ofi.AtEndOfStream != true) {
		ln = ofi.ReadLine();
		s = new String(ln);
		if (s.search(/\@VERSION\@/) != -1) {
			of.WriteLine(s.replace(/\@VERSION\@/,
				verMajorLibEETSigner + "." + verMinorLibEETSigner + "." + verMicroLibEETSigner));
		} else if (s.search(/\@VERSION2\@/) != -1) {
			of.WriteLine(s.replace(/\@VERSION2\@/,
				verMajorLibEETSigner + "," + verMinorLibEETSigner + "," + verMicroLibEETSigner + ",0"));
		} else
			of.WriteLine(ln);
	}
	ofi.Close();
	of.Close();
}

function configureVersionH()
{
	fso = new ActiveXObject("Scripting.FileSystemObject");
	ofi = fso.OpenTextFile(verhFileIn, 1);
	of = fso.CreateTextFile(verhFile, true);
	while (ofi.AtEndOfStream != true) {
		ln = ofi.ReadLine();
		s = new String(ln);
		if (s.search(/\@VERSION\@/) != -1) {
			of.WriteLine(s.replace(/\@VERSION\@/,
				verMajorLibEETSigner + "." + verMinorLibEETSigner + "." + verMicroLibEETSigner));
		} else if (s.search(/\@LIBEET_VERSION_MAJOR\@/) != -1) {
			of.WriteLine(s.replace(/\@LIBEET_VERSION_MAJOR\@/,
				verMajorLibEETSigner));
		} else if (s.search(/\@LIBEET_VERSION_MINOR\@/) != -1) {
			of.WriteLine(s.replace(/\@LIBEET_VERSION_MINOR\@/,
				verMinorLibEETSigner));
		} else if (s.search(/\@LIBEET_VERSION_SUBMINOR\@/) != -1) {
			of.WriteLine(s.replace(/\@LIBEET_VERSION_SUBMINOR\@/,
				verMicroLibEETSigner));
		} else
			of.WriteLine(ln);
	}
	ofi.Close();
	of.Close();
} 

/* Creates the readme file for the binary distribution of 'bname', for the
   version 'ver' in the file 'file'. This one is called from the Makefile when
   generating a binary distribution. The parameters are passed by make. */
function genReadme(bname, ver, splatform, file)
{
	var fso, f;
	fso = new ActiveXObject("Scripting.FileSystemObject");
	f = fso.CreateTextFile(file, true);
	f.WriteLine("  " + bname + " " + ver);
	f.WriteLine("  ------------------");
	f.WriteBlankLines(1);
	f.WriteLine("  This is " + bname + ", version " + ver + ", binary package for the native " + splatform );
	f.WriteLine("platform.");
	f.WriteBlankLines(1);
	f.WriteLine("  The files in this package require \"Microsoft Visual C++ 2013 Redistributable (" + buildPlatform+ ")\".");
	f.WriteLine("  ");
	f.WriteLine("  Extract the contents of the archive whereever you wish and");
	f.WriteLine("make sure that your tools which use " + bname + " can find it.");
	f.WriteBlankLines(1);
	f.WriteLine("  For example, if you want to run the supplied utilities from the command");
	f.WriteLine("line, you can, if you wish, add the 'bin' subdirectory to the PATH");
	f.WriteLine("environment variable.");
	f.WriteLine("  If you want to make programmes in C which use " + bname + ", you'll");
	f.WriteLine("likely know how to use the contents of this package. If you don't, please");
	f.WriteLine("refer to your compiler's documentation.");
	f.WriteBlankLines(1);
	f.WriteLine("  If there is something you cannot keep for yourself, such as a problem,");
	f.WriteLine("a cheer of joy, a comment or a suggestion, feel free to contact me using");
	f.WriteLine("the address below.");
	f.WriteBlankLines(1);
	f.WriteLine("Miroslav Kundela (mail@mirus.cz)");
	f.Close();
}

discoverBuildPlatform();

/*
 * main(),
 * Execution begins here.
 */

/* Parse the command-line arguments. */
for (i = 0; (i < WScript.Arguments.length) && (error == 0); i++) {
	var arg, opt;
	arg = WScript.Arguments(i);
	opt = arg.substring(0, arg.indexOf("="));
	if (opt.length == 0)
		opt = arg.substring(0, arg.indexOf(":"));
	if (opt.length > 0) {
		if (opt == "crypto")
			withCrypto = arg.substring(opt.length + 1, arg.length);
		else if (opt == "xslt")
			withLibXSLT = strToBool(arg.substring(opt.length + 1, arg.length));
		else if (opt == "iconv")
			withIconv = strToBool(arg.substring(opt.length + 1, arg.length));
		else if (opt == "nt4")
			withNT4 = strToBool(arg.substring(opt.length + 1, arg.length));
		else if (opt == "unicode")
			buildUnicode = strToBool(arg.substring(opt.length + 1, arg.length));
		else if (opt == "debug")
			buildDebug = strToBool(arg.substring(opt.length + 1, arg.length));
		else if (opt == "static")
			buildStatic = strToBool(arg.substring(opt.length + 1, arg.length));
		else if (opt == "with-dl")
			buildWithDLSupport = strToBool(arg.substring(opt.length + 1, arg.length));
		else if (opt == "prefix")
			buildPrefix = arg.substring(opt.length + 1, arg.length);
		else if (opt == "incdir")
			buildIncPrefix = arg.substring(opt.length + 1, arg.length);
		else if (opt == "bindir")
			buildBinPrefix = arg.substring(opt.length + 1, arg.length);
		else if (opt == "libdir")
			buildLibPrefix = arg.substring(opt.length + 1, arg.length);
		else if (opt == "sodir")
			buildSoPrefix = arg.substring(opt.length + 1, arg.length);
		else if (opt == "incdir")
			buildIncPrefix = arg.substring(opt.length + 1, arg.length);
		else if (opt == "include")
			buildInclude = arg.substring(opt.length + 1, arg.length);
		else if (opt == "lib")
			buildLib = arg.substring(opt.length + 1, arg.length);
		else if (opt == "cruntime")
			cruntime = arg.substring(opt.length + 1, arg.length);
		else
			error = 1;
	} else if (i == 0) {
		if (arg == "genreadme") {
			// This command comes from the Makefile and will not be checked
			// for errors, because Makefile will always supply right parameters.
			genReadme(WScript.Arguments(1), WScript.Arguments(2), WScript.Arguments(3), WScript.Arguments(4));
			WScript.Quit(0);
		} else if (arg == "help") {
			usage();
			WScript.Quit(0);
		}
	} else
		error = 1;
}
// If we have an error here, it is because the user supplied bad parameters.
if (error != 0) {
	usage();
	WScript.Quit(error);
}

// if user choses to link the c-runtime library statically into libxml2
// with /MT and friends, then we need to enable static linking for xmllint
if (cruntime == "/MT" || cruntime == "/MTd" ||
    cruntime == "/ML" || cruntime == "/MLd") {
    buildStatic = 1;
}

// Discover the version.
discoverVersion();
if (error != 0) {
	WScript.Echo("Version discovery failed, aborting.");
	WScript.Quit(error);
}
WScript.Echo(baseName + " version: " + verMajorLibEETSigner + "." + verMinorLibEETSigner + "." + verMicroLibEETSigner);
WScript.Echo("Build Platform : " + buildPlatform);



// Configure libxmlsec.
configureLibEET();
if (error != 0) {
	WScript.Echo("Configuration failed, aborting.");
	WScript.Quit(error);
}

configureVersion32()
if (error != 0) {
	WScript.Echo("Generate version32.rc failed, aborting.");
	WScript.Quit(error);
}

configureVersionH()
if (error != 0) {
	WScript.Echo("Generate libeet/version.h failed, aborting.");
	WScript.Quit(error);
}

// Create the Makefile.
var fso = new ActiveXObject("Scripting.FileSystemObject");
fso.CopyFile(".\\Makefile.msvc", ".\\Makefile", true);
WScript.Echo("Created Makefile.");

// Display the final configuration.
var txtOut = "\nlibEETSigner configuration\n";
txtOut += "----------------------------\n";
txtOut += "\n";
txtOut += "Win32 build configuration\n";
txtOut += "-------------------------\n";
txtOut += "            Unicode: " + boolToStr(buildUnicode) + "\n";
txtOut += "      Debug symbols: " + boolToStr(buildDebug) + "\n";
txtOut += "     Install prefix: " + buildPrefix + "\n";
txtOut += "       Put tools in: " + buildBinPrefix + "\n";
txtOut += "     Put headers in: " + buildIncPrefix + "\n";
txtOut += " Put static libs in: " + buildLibPrefix + "\n";
txtOut += " Put shared libs in: " + buildSoPrefix + "\n";
txtOut += "       Include path: " + buildInclude + "\n";
txtOut += "           Lib path: " + buildLib + "\n";
txtOut += "Use OpenSSL Version: " + withOpenSSLVersion + "\n";
txtOut += "   C-Runtime option: " + cruntime + "\n";
txtOut += "            Static : " + boolToStr(buildStatic) + "\n";
WScript.Echo(txtOut);

// Done.
