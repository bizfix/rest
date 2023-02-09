package rest

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

var allMethods = []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodConnect, http.MethodOptions, http.MethodTrace}

func newSpec(name string) *openapi3.T {
	return &openapi3.T{
		OpenAPI: "3.0.0",
		Info: &openapi3.Info{
			Title:      name,
			Version:    "0.0.0",
			Extensions: map[string]interface{}{},
		},
		Components: &openapi3.Components{
			Schemas:    make(openapi3.Schemas),
			Extensions: map[string]interface{}{},
		},
		Paths:      openapi3.Paths{},
		Extensions: map[string]interface{}{},
	}
}

func (api *API) createOpenAPI() (spec *openapi3.T, err error) {
	spec = newSpec(api.Name)
	// Add all the routes.
	for _, r := range api.Routes {
		path := &openapi3.PathItem{}
		methodToOperation := make(map[string]*openapi3.Operation)
		for _, method := range allMethods {
			if models, hasMethod := r.MethodToModels[method]; hasMethod {
				op := &openapi3.Operation{}

				// Handle request types.
				if models.Request.Type != nil {
					ref, err := api.getSchema(spec.Components.Schemas, models.Request.Type, getSchemaOpts{})
					if err != nil {
						return spec, err
					}
					op.RequestBody = &openapi3.RequestBodyRef{
						Value: &openapi3.RequestBody{
							Description: "",
							Content: map[string]*openapi3.MediaType{
								"application/json": {
									Schema: ref,
								},
							},
						},
					}
				}

				// Handle response types.
				for status, model := range models.Responses {
					ref, err := api.getSchema(spec.Components.Schemas, model.Type, getSchemaOpts{})
					if err != nil {
						return spec, err
					}
					op.AddResponse(status, &openapi3.Response{
						Description: pointerTo(""),
						Content: map[string]*openapi3.MediaType{
							"application/json": {
								Schema: ref,
							},
						},
					})
				}

				// Register the method.
				methodToOperation[method] = op
			}
		}

		// Register the routes.
		for method, operation := range methodToOperation {
			switch method {
			case http.MethodGet:
				path.Get = operation
			case http.MethodHead:
				path.Head = operation
			case http.MethodPost:
				path.Post = operation
			case http.MethodPut:
				path.Put = operation
			case http.MethodPatch:
				path.Patch = operation
			case http.MethodDelete:
				path.Delete = operation
			case http.MethodConnect:
				path.Connect = operation
			case http.MethodOptions:
				path.Options = operation
			case http.MethodTrace:
				path.Trace = operation
			default:
				return spec, fmt.Errorf("unknown HTTP method: %v", method)
			}
		}
		spec.Paths[r.Path] = path
	}

	data, err := spec.MarshalJSON()
	if err != nil {
		return spec, fmt.Errorf("failed to marshal spec to/from JSON: %w", err)
	}
	spec, err = openapi3.NewLoader().LoadFromData(data)
	if err != nil {
		return spec, fmt.Errorf("failed to load spec to/from JSON: %w", err)
	}
	if err = spec.Validate(context.Background()); err != nil {
		return spec, fmt.Errorf("failed validation: %w", err)
	}

	return spec, err
}

func pointerTo[T any](v T) *T {
	return &v
}

type getSchemaOpts struct {
	IsPointer  bool
	IsEmbedded bool
}

func (api *API) getSchema(schemas openapi3.Schemas, t reflect.Type, opts getSchemaOpts) (s *openapi3.SchemaRef, err error) {
	// Normalize the name.
	pkgPath, typeName := t.PkgPath(), t.Name()
	if t.Kind() == reflect.Pointer {
		pkgPath = t.Elem().PkgPath()
		typeName = t.Elem().Name() + "Ptr"
	}
	schemaName := api.normalizeTypeName(pkgPath, typeName)
	if typeName == "" {
		schemaName = fmt.Sprintf("AnonymousType%d", len(schemas))
	}
	// If we've already got the schema, return it.
	if _, hasExisting := schemas[schemaName]; hasExisting {
		return openapi3.NewSchemaRef(fmt.Sprintf("#/components/schemas/%s", schemaName), nil), nil
	}
	// It's known, but not int the schemaset yet.
	if known, isKnown := api.KnownTypes[t]; isKnown {
		// Add it.
		schemas[schemaName] = openapi3.NewSchemaRef("", known)
		// Return a reference to it.
		return openapi3.NewSchemaRef(fmt.Sprintf("#/components/schemas/%s", schemaName), nil), nil
	}

	switch t.Kind() {
	case reflect.Slice, reflect.Array:
		arraySchema := openapi3.NewArraySchema()
		arraySchema.Nullable = true // Arrays are always nilable in Go.
		arraySchema.Items, err = api.getSchema(schemas, t.Elem(), getSchemaOpts{})
		if err != nil {
			return
		}
		return openapi3.NewSchemaRef("", arraySchema), nil
	case reflect.String:
		return openapi3.NewSchemaRef("", &openapi3.Schema{
			Type:     openapi3.TypeString,
			Nullable: opts.IsPointer,
		}), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return openapi3.NewSchemaRef("", &openapi3.Schema{
			Type:     openapi3.TypeInteger,
			Nullable: opts.IsPointer,
		}), nil
	case reflect.Float64, reflect.Float32:
		return openapi3.NewSchemaRef("", &openapi3.Schema{
			Type:     openapi3.TypeNumber,
			Nullable: opts.IsPointer,
		}), nil
	case reflect.Bool:
		return openapi3.NewSchemaRef("", &openapi3.Schema{
			Type:     openapi3.TypeBoolean,
			Nullable: opts.IsPointer,
		}), nil
	case reflect.Pointer:
		ref, err := api.getSchema(schemas, t.Elem(), getSchemaOpts{IsPointer: true})
		if err != nil {
			return nil, fmt.Errorf("error getting schema of pointer to %v: %w", t.Elem(), err)
		}
		return ref, err
	case reflect.Struct:
		schema := openapi3.NewObjectSchema()
		schema.Properties = make(openapi3.Schemas)
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			// Get JSON name.
			name := strings.Split(f.Tag.Get("json"), ",")[0]
			if name == "" {
				name = f.Name
			}
			if f.Anonymous {
				// Add all the embedded fields to this type.
				// Create an empty
				embedded, err := api.getSchema(schemas, f.Type, getSchemaOpts{IsEmbedded: true})
				if err != nil {
					return nil, fmt.Errorf("error getting schema of embedded type: %w", err)
				}
				// If there's no value, then the embedded type must already be added to the schemaset.
				// So fetch it from there.
				if embedded.Value == nil {
					embedded = schemas[strings.TrimPrefix(embedded.Ref, "#/components/schemas/")]
				}
				for name, ref := range embedded.Value.Properties {
					schema.Properties[name] = ref
				}
				continue
			}
			schema.Properties[name], err = api.getSchema(schemas, f.Type, getSchemaOpts{})
		}
		value := openapi3.NewSchemaRef("", schema)
		if opts.IsEmbedded {
			return value, nil
		}
		schemas[schemaName] = value

		// Return a reference.
		return openapi3.NewSchemaRef(fmt.Sprintf("#/components/schemas/%s", schemaName), nil), nil
	}

	return nil, fmt.Errorf("unsupported type: %v/%v", t.PkgPath(), t.Name())
}

var normalizer = strings.NewReplacer("/", "_", ".", "_")

func (api *API) normalizeTypeName(pkgPath, name string) string {
	var omitPackage bool
	for _, pkg := range api.StripPkgPaths {
		if strings.HasPrefix(pkgPath, pkg) {
			omitPackage = true
			break
		}
	}
	if omitPackage {
		return normalizer.Replace(name)
	}
	return normalizer.Replace(pkgPath + "/" + name)
}
