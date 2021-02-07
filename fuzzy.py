from fuzzywuzzy import fuzz, process

def return_results(list_of_dicts, query, threshold=5):
    scores = []
    for index, item in enumerate(list_of_dicts):
        values = item["name"].split(" ")

        if item["nickname"] != "":
            values.append(item["nickname"])

        ratios = [
            fuzz.ratio(str(query), str(value)) for value in values
        ]  # ensure both are in string
        scores.append({"index": index, "score": max(ratios)})

    # print("SCORES" , scores)

    filtered_scores = [item for item in scores if item["score"] >= threshold]
    sorted_filtered_scores = sorted(filtered_scores, key=lambda k: k["score"], reverse=True)
    filtered_list_of_dicts = [list_of_dicts[item["index"]] for item in sorted_filtered_scores]
    return filtered_list_of_dicts


"""
Using it
search_results = return_results(list_of_dicts, query)
print("\n\n")
for el in search_results:
    print("VALUES - {0} \n".format(el['name']))
"""
