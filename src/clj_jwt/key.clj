(ns clj-jwt.key
  (:require [clojure.java.io :as io])
  (:import  [org.bouncycastle.openssl PEMParser PEMKeyPair PEMEncryptedKeyPair]
            [org.bouncycastle.openssl.jcajce JcaPEMKeyConverter JcePEMDecryptorProviderBuilder]
            [org.bouncycastle.asn1.pkcs PrivateKeyInfo]
            [org.bouncycastle.asn1.x509 SubjectPublicKeyInfo]
            [org.bouncycastle.cert X509CertificateHolder]
            [java.io StringReader]))

(defprotocol GetPrivateKey
  (-get-private-key [key-info password]))

(defprotocol GetPublicKey
  (-get-public-key [key-info password]))

(defn ^JcaPEMKeyConverter pem-converter []
  (JcaPEMKeyConverter.))

(extend-protocol GetPrivateKey
  PrivateKeyInfo
  (-get-private-key [key-info _]
    (-> (pem-converter)
        (.getPrivateKey key-info))))

(extend-protocol GetPublicKey
  SubjectPublicKeyInfo
  (-get-public-key [key-info _]
    (-> (pem-converter)
        (.getPublicKey key-info)))
  X509CertificateHolder
  (-get-public-key [key-info password]
    (-get-public-key (.getSubjectPublicKeyInfo key-info) password)))

(extend-type PEMKeyPair
  GetPrivateKey
  (-get-private-key [key-info _]
    (-> (pem-converter)
        (.getKeyPair key-info)
        .getPrivate))

  GetPublicKey
  (-get-public-key [key-info _]
    (-> (pem-converter)
        (.getKeyPair key-info)
        .getPublic)))

(extend-type PEMEncryptedKeyPair
  GetPrivateKey
  (-get-private-key [key-info ^String password]
    (let [dec-prov (-> (JcePEMDecryptorProviderBuilder.)
                       (.build (.toCharArray password)))]
      (-get-private-key (-> key-info
                           (.decryptKeyPair dec-prov)) nil)))
  GetPublicKey
  (-get-public-key [key-info ^String password]
    (let [dec-prov (-> (JcePEMDecryptorProviderBuilder.)
                       (.build (.toCharArray password)))]
      (-get-public-key (-> key-info
                           (.decryptKeyPair dec-prov)) nil))))

(defn pem->public-key [reader pass-phrase]
  (-get-public-key (.readObject (PEMParser. reader)) pass-phrase))

(defn pem->private-key [reader pass-phrase]
  (-get-private-key (.readObject (PEMParser. reader)) pass-phrase))

(defn private-key
  [filename & [pass-phrase]]
  (with-open [r (io/reader filename)]
    (pem->private-key r pass-phrase)))

(defn public-key
  [filename & [pass-phrase]]
  (with-open [r (io/reader filename)]
    (pem->public-key r pass-phrase)))

(defn public-key-from-string
  [key-str & [pass-phrase]]
  (with-open [r (StringReader. key-str)]
    (pem->public-key r pass-phrase)))
