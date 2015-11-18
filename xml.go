package main

import (
	"encoding/xml"
	"fmt"
	metapb "github.com/clawio/service.localstore.meta/proto"
	"path"
	"time"
)

func metaToXML(meta *metapb.Metadata) ([]byte, error) {

	responses := []*responseXML{}

	parentResponse, err := metaToPropResponse(meta)
	if err != nil {
		return []byte{}, err
	}

	responses = append(responses, parentResponse)
	if len(meta.Children) > 0 {
		for _, m := range meta.Children {
			childResponse, err := metaToPropResponse(m)
			if err != nil {
				return []byte{}, err
			}
			responses = append(responses, childResponse)
		}
	}

	responsesXML, err := xml.Marshal(&responses)
	if err != nil {
		return []byte{}, err
	}

	msg := `<?xml version="1.0" encoding="utf-8"?><d:multistatus xmlns:d="DAV:" `
	msg += `xmlns:s="http://sabredav.org/ns" xmlns:oc="http://owncloud.org/ns">`
	msg += string(responsesXML) + `</d:multistatus>`

	return []byte(msg), nil
}

func metaToPropResponse(meta *metapb.Metadata) (*responseXML, error) {

	// TODO: clean a little bit this and refactor creation of properties
	propList := []propertyXML{}

	// Attributes
	quotaUsedBytes := propertyXML{
		xml.Name{Space: "", Local: "d:quota-used-bytes"}, "", []byte("0")}

	quotaAvailableBytes := propertyXML{
		xml.Name{Space: "", Local: "d:quota-available-bytes"}, "",
		[]byte("1000000000")}

	t := time.Unix(int64(meta.Modified), 0)
	lasModifiedString := t.Format(time.RFC1123)

	getContentLegnth := propertyXML{
		xml.Name{Space: "", Local: "d:getcontentlength"},
		"", []byte(fmt.Sprintf("%d", meta.Size))}

	getLastModified := propertyXML{
		xml.Name{Space: "", Local: "d:getlastmodified"},
		"", []byte(lasModifiedString)}

	getETag := propertyXML{
		xml.Name{Space: "", Local: "d:getetag"},
		"", []byte(meta.Etag)}

	getContentType := propertyXML{
		xml.Name{Space: "", Local: "d:getcontenttype"},
		"", []byte(meta.MimeType)}

	if meta.IsContainer {
		getResourceType := propertyXML{
			xml.Name{Space: "", Local: "d:resourcetype"},
			"", []byte("<d:collection/>")}

		getContentType.InnerXML = []byte("inode/container")
		propList = append(propList, getResourceType)
	}

	ocID := propertyXML{xml.Name{Space: "", Local: "oc:id"}, "",
		[]byte(meta.Id)}

	ocDownloadURL := propertyXML{xml.Name{Space: "", Local: "oc:downloadURL"},
		"", []byte("")}

	ocDC := propertyXML{xml.Name{Space: "", Local: "oc:dDC"},
		"", []byte("")}

	ocPermissions := propertyXML{xml.Name{Space: "", Local: "oc:permissions"},
		"", []byte("RDNVCK")}

	propList = append(propList, getContentLegnth,
		getLastModified, getETag, getContentType, quotaUsedBytes,
		quotaAvailableBytes, ocID, ocDC, ocDownloadURL, ocPermissions)

	// PropStat, only HTTP/1.1 200 is sent.
	propStatList := []propstatXML{}

	propStat := propstatXML{}
	propStat.Prop = propList
	propStat.Status = "HTTP/1.1 200 OK"
	propStatList = append(propStatList, propStat)

	response := responseXML{}

	response.Href = path.Join("/", meta.Path)

	response.Propstat = propStatList

	return &response, nil
}

type responseXML struct {
	XMLName             xml.Name      `xml:"d:response"`
	Href                string        `xml:"d:href"`
	Propstat            []propstatXML `xml:"d:propstat"`
	Status              string        `xml:"d:status,omitempty"`
	Error               *errorXML     `xml:"d:error"`
	ResponseDescription string        `xml:"d:responsedescription,omitempty"`
}

// http://www.ocwebdav.org/specs/rfc4918.html#ELEMENT_propstat
type propstatXML struct {
	// Prop requires DAV: to be the default namespace in the enclosing
	// XML. This is due to the standard encoding/xml package currently
	// not honoring namespace declarations inside a xmltag with a
	// parent element for anonymous slice elements.
	// Use of multistatusWriter takes care of this.
	Prop                []propertyXML `xml:"d:prop>_ignored_"`
	Status              string        `xml:"d:status"`
	Error               *errorXML     `xml:"d:error"`
	ResponseDescription string        `xml:"d:responsedescription,omitempty"`
}

// Property represents a single DAV resource property as defined in RFC 4918.
// http://www.ocwebdav.org/specs/rfc4918.html#data.model.for.resource.properties
type propertyXML struct {
	// XMLName is the fully qualified name that identifies this property.
	XMLName xml.Name

	// Lang is an optional xml:lang attribute.
	Lang string `xml:"xml:lang,attr,omitempty"`

	// InnerXML contains the XML representation of the property value.
	// See http://www.ocwebdav.org/specs/rfc4918.html#property_values
	//
	// Property values of complex type or mixed-content must have fully
	// expanded XML namespaces or be self-contained with according
	// XML namespace declarations. They must not rely on any XML
	// namespace declarations within the scope of the XML document,
	// even including the DAV: namespace.
	InnerXML []byte `xml:",innerxml"`
}

// http://www.ocwebdav.org/specs/rfc4918.html#ELEMENT_error
type errorXML struct {
	XMLName  xml.Name `xml:"d:error"`
	InnerXML []byte   `xml:",innerxml"`
}
