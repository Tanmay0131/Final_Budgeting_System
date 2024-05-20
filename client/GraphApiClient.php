<?php

namespace GetUser\Client;

use GetUser\Client\Me\MeRequestBuilder;
use Microsoft\Kiota\Abstractions\ApiClientBuilder;
use Microsoft\Kiota\Abstractions\BaseRequestBuilder;
use Microsoft\Kiota\Abstractions\RequestAdapter;
use Microsoft\Kiota\Serialization\Json\JsonParseNodeFactory;
use Microsoft\Kiota\Serialization\Json\JsonSerializationWriterFactory;
use Microsoft\Kiota\Serialization\Text\TextParseNodeFactory;
use Microsoft\Kiota\Serialization\Text\TextSerializationWriterFactory;

/**
 * The main entry point of the SDK, exposes the configuration and the fluent API.
*/
class GraphApiClient extends BaseRequestBuilder 
{
    /**
     * The me property
    */
    public function me(): MeRequestBuilder {
        return new MeRequestBuilder($this->pathParameters, $this->requestAdapter);
    }
    
    /**
     * Instantiates a new GraphApiClient and sets the default values.
     * @param RequestAdapter $requestAdapter The request adapter to use to execute the requests.
    */
    public function __construct(RequestAdapter $requestAdapter) {
        parent::__construct($requestAdapter, [], '{+baseurl}');
        ApiClientBuilder::registerDefaultSerializer(JsonSerializationWriterFactory::class);
        ApiClientBuilder::registerDefaultSerializer(TextSerializationWriterFactory::class);
        ApiClientBuilder::registerDefaultDeserializer(JsonParseNodeFactory::class);
        ApiClientBuilder::registerDefaultDeserializer(TextParseNodeFactory::class);
        if (empty($this->requestAdapter->getBaseUrl())) {
            $this->requestAdapter->setBaseUrl('https://graph.microsoft.com/v1.0');
        }
        $this->pathParameters['baseurl'] = $this->requestAdapter->getBaseUrl();
    }

}
//https://login.microsoftonline.com/common/oauth2/v2.0/authorize?tenant_id=e34fd78b-f48d-4235-9787-fef76723be14&client_id=baf988fb-4544-4dcf-a47d-4e21a533c2db&response_type=code&redirect_uri=http%3A%2F%2Flocalhost&response_mode=query&scope=User.Read

//https://login.microsoftonline.com/e34fd78b-f48d-4235-9787-fef76723be14/oauth2/v2.0/authorize?client_id=baf988fb-4544-4dcf-a47d-4e21a533c2db&response_type=code&redirect_uri=http%3A%2F%2Flocalhost&response_mode=query&scope=User.Read
