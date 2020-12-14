# {{classname}}

All URIs are relative to */v1*

Method | HTTP request | Description
------------- | ------------- | -------------
[**JoinChannel**](ChannelsApi.md#JoinChannel) | **Post** /channels | Joins an Ordering Service Node (OSN) to a channel.
[**ListChannel**](ChannelsApi.md#ListChannel) | **Get** /channels/{channelID} | Returns detailed channel information for a specific channel Ordering Service Node (OSN) has joined.
[**ListChannels**](ChannelsApi.md#ListChannels) | **Get** /channels | Returns the complete list of channels an Ordering Service Node (OSN) has joined.
[**RemoveChannel**](ChannelsApi.md#RemoveChannel) | **Delete** /channels/{channelID} | Removes an Ordering Service Node (OSN) from a channel.

# **JoinChannel**
> ChannelInfo JoinChannel(ctx, body)
Joins an Ordering Service Node (OSN) to a channel.

If a channel does not yet exist, it will be created.

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **body** | [**Body**](Body.md)|  | 

### Return type

[**ChannelInfo**](channelInfo.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ListChannel**
> ChannelInfo ListChannel(ctx, channelID)
Returns detailed channel information for a specific channel Ordering Service Node (OSN) has joined.

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **channelID** | **string**| Channel ID | 

### Return type

[**ChannelInfo**](channelInfo.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ListChannels**
> ChannelList ListChannels(ctx, )
Returns the complete list of channels an Ordering Service Node (OSN) has joined.

### Required Parameters
This endpoint does not need any parameter.

### Return type

[**ChannelList**](channelList.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **RemoveChannel**
> RemoveChannel(ctx, channelID)
Removes an Ordering Service Node (OSN) from a channel.

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **channelID** | **string**| Channel ID | 

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

