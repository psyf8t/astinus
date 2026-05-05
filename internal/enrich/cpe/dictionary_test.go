package cpe

import "testing"

func TestBundledDictionaryLoadAndLookup(t *testing.T) {
	d := Default()
	if err := d.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if d.Len() == 0 {
		t.Fatal("dictionary empty after load")
	}
	if d.Snapshot() == "" {
		t.Error("Snapshot date should be populated")
	}

	cases := []struct {
		typ, ns, name string
		wantVendor    string
		wantProduct   string
	}{
		{"npm", "", "express", "expressjs", "express"},
		{"pypi", "", "django", "djangoproject", "django"},
		{"maven", "org.apache.logging.log4j", "log4j-core", "apache", "log4j"},
		{"deb", "debian", "openssl", "openssl", "openssl"},
		{"apk", "alpine", "musl", "musl-libc", "musl"},
	}
	for _, c := range cases {
		entry, ok := d.Lookup(c.typ, c.ns, c.name)
		if !ok {
			t.Errorf("Lookup(%q,%q,%q) not found", c.typ, c.ns, c.name)
			continue
		}
		if entry.Vendor != c.wantVendor || entry.Product != c.wantProduct {
			t.Errorf("Lookup(%q,%q,%q) = (%q,%q), want (%q,%q)",
				c.typ, c.ns, c.name, entry.Vendor, entry.Product, c.wantVendor, c.wantProduct)
		}
	}
}

func TestBundledDictionaryLookupCaseInsensitive(t *testing.T) {
	d := Default()
	if _, ok := d.Lookup("NPM", "", "Express"); !ok {
		t.Error("expected case-insensitive lookup to succeed")
	}
}

func TestBundledDictionaryLookupMiss(t *testing.T) {
	d := Default()
	if _, ok := d.Lookup("npm", "", "definitely-not-a-package-7384"); ok {
		t.Error("expected miss for unknown name")
	}
}
