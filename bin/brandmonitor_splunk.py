from splunklib.searchcommands import \
    dispatch, GeneratingCommand, Configuration, Option, validators
import splunklib.client as client
import zipfile
import urllib2
import io
import fnmatch
import re
import sys
import time

@Configuration()
class BrandMonitorCommand(GeneratingCommand):

    brandnames = Option(require=True, validate=None)
    wildcards = Option(require=True, validate=None)
    date = Option(require=True, validate=None)

    def generate(self):

        # Basic argument checks

        brandnames = self.brandnames.split(",")
        wildcards = self.wildcards.split(",")

        if(len(brandnames) != len(wildcards)):
            self.logger.fatal("Number of brandnames and wildcards has to be equal, is " +
                              str(len(brandnames)) + ", " + str(len(wildcards)))
            exit(1)

        if len(re.findall("\d{4}-\d{2}-\d{2}",self.date)) != 1:
            self.logger.fatal("date has to be in format YYYY-MM-DD, is " + self.date)
            exit(1)

        url = "https://whoisds.com//whois-database/newly-registered-domains/" + self.date + ".zip/nrd"

        # download stream from url

        self.logger.fatal("Starting download from url " + url)

        response = ""

        try:
            opener = urllib2.build_opener()
            opener.addheaders = [('User-Agent', 'Mozilla/5.0')]
            response = opener.open(url)
        except urllib2.HTTPError as e:
            self.logger.fatal(e.read())
            exit(1)

        # check if downloaded stream is empty

        downloadedStream = response.read()

        if len(downloadedStream) == 0:
            self.logger.fatal("Downloaded file is empty")
            exit(1)

        # convert to file

        downloadedFile = io.BytesIO(downloadedStream)

        domainlist = ""

        # try to unzip file

        try:
            domainlist = zipfile.ZipFile(downloadedFile).open("domain-names.txt").read().split()
        except zipfile.BadZipfile as e:
            self.logger.fatal("Downloaded file is not a zip file")
            exit(1)

        self.logger.fatal("downloaded " + str(len(domainlist)) + " new domains")



        for i in range(0, len(brandnames)):

            brandname = brandnames[i]
            wildcard = wildcards[i]

            try:
                wildcard = int(wildcard)
            except TypeError as e:
                self.logger.fatal("wildcards has to be a number, is " + wildcard)
                exit(1)

            if (wildcard < 0) or (wildcard > 3):
                self.logger.fatal("wildcards has to be between 0 and 3, is " + str(wildcard))
                exit(1)

            if (len(brandname) == 0):
                self.logger.fatal("brandname has to be defined")
                exit(1)

            # build list to match against with 0-3 wildcards in the brandname

            matchList = [brandname]

            if wildcard > 0:
                for i in range(0, len(brandname)):
                    matchList.append(str(brandname[:i] + "*" + brandname[i + 1:]))

            if wildcard > 1:
                for i in range(0, len(brandname)):
                    for j in range(i+1, len(brandname)):
                        matchList.append(str(brandname[:i] + "*" + brandname[i + 1:j] + "*" + brandname[j + 1:]))

            if wildcard > 2:
                for i in range(0, len(brandname)):
                    for j in range(i+1, len(brandname)):
                        for k in range(j+1, len(brandname)):
                            matchList.append(str(brandname[:i] + "*" + brandname[i + 1:j] + "*" + brandname[j + 1:k] + "*" + brandname[k + 1:]))

            self.logger.fatal("Trying to match with " + str(matchList))

            # match the list against the downloaded domains

            resultListWithDuplicates = []

            for i in range(0,len(matchList)):
                filtered = fnmatch.filter(domainlist,matchList[i])
                if len(filtered) > 0:
                    resultListWithDuplicates.extend(filtered)

            # dedup the resulting domain names

            resultList = []

            for i in resultListWithDuplicates:
              if i not in resultList:
                resultList.append(i)

            for i in resultList:
                yield {'_time': (time.strftime("%s",time.strptime(self.date,"%Y-%m-%d"))), 'sourcetype': "stash", '_raw': "domain=" + i}

dispatch(BrandMonitorCommand, sys.argv, sys.stdin, sys.stdout, __name__)
