#******************************************************************************#
#                                                                              #
#                          Lab 2 - CPE Standard                                #
#                                                                              #
#              Arnau Sangra Rocamora - Data Driven Securty                     #
#                                                                              #
#******************************************************************************#

if (!require("xml2")) {
 install.packages("xml2")
}

library(xml2)

if (!require("stringr")) {
  install.packages("stringr")
}

if (!require("tidyr")) {
  install.packages("tidyr")
}

if (!require("dplyr")) {
  install.packages("dplyr")
}

library(stringr)

library(dplyr)
library(tidyr)


cpe.file <- "./official-cpe-dictionary_v2.3.xml"
if (!file.exists(cpe.file)) {
  compressed_cpes_url <- "https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.zip"
  cpes_filename <- "cpes.zip"
  download.file(compressed_cpes_url, cpes_filename)
  unzip(zipfile = cpes_filename)
  cpe.file <- "./official-cpe-dictionary_v2.3.xml"
}


GetCPEItems <- function(cpe.raw) {

  #https://rdrr.io/github/r-net-tools/net.security/src/R/cpe.R

  cpes <- data.frame(title = xml2::xml_text(xml2::xml_find_all(cpe.raw, "//d1:cpe-item/d1:title[@xml:lang='en-US']/text()")),
                     name = xml2::xml_attr(xml2::xml_find_all(cpe.raw, "//d1:cpe-item"), "name"),
                     cpe.23 = xml2::xml_text(xml2::xml_find_all(cpe.raw, "//cpe-23:cpe23-item/@name")),
                     stringsAsFactors = F)
  # return data frame

  return(cpes)
}


CleanCPEs <- function(cpes){

  # data manipulation

  colnames <- c("cpe23.type", "cpe23.manuf" , "cpe23.prod", "cpe23.version", "cpe23.other1",
                "cpe23.other2","cpe23.other2","cpe23.other3","cpe23.other4","cpe23.other5",
                "cpe23.other6")

  cpe23 <- str_split_fixed(cpes$cpe.23, ':', 13)
  cpe23 <- as.data.frame(cpe23)
  cpe23 <- select(cpe23, 3:13)
  colnames(cpe23) <- colnames
  bind_cols(cpes, cpe23)
#  cpe23 <- sapply(list, function)

}

ParseCPEData <- function(cpe.file) {

  # load cpes as xml file
  cpes <- xml2::read_xml(x = cpe.file, '')

  # get CPEs
  cpes <- GetCPEItems(cpes)

  # transform, clean, arrange parsed cpes as data frame
  df <- CleanCPEs(cpes)

  # return data frame
  return(df)
}
