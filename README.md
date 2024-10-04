# jsonfilter

Apply filters defined as JSON strings to arbitrary Gp structs.

For example, having the following object:

```go
type Internal struct {
    data string
}
type MyData struct {
    internal Internal
    what int
}

obj := MyData {
    what: 5,
    data: Internal{
        data: "nope"
    }
}
```

And the filter:

```json
{
    "$or": [
        {
            "internal.data": {
                "$eq": "something"
            }
        },
        {
            "$and": [
                {
                    "what": {
                        "$gt": 1
                    },
                },
                {
                    "what": {
                        "$lt": 10
                    }
                }
            ]
        }
    ]
}
```

It would return true.