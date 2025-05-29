import data from '../../../SumPatches_output.json';

export const getDataByMonth = (monthId) => {
  // Convert your data format from yyyy-mm to match the date format in your JSON
  const [year, month] = monthId.split('-');
  return data.filter(item => {
    const itemDate = new Date(item.date);
    return itemDate.getFullYear() === parseInt(year) && 
           (itemDate.getMonth() + 1) === parseInt(month);
  });
};