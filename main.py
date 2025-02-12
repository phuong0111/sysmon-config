import streamlit as st
import pandas as pd
import plotly.express as px
import seaborn as sns
import matplotlib.pyplot as plt

# Set page configuration
st.set_page_config(
    page_title="CSV Data Visualizer",
    page_icon="📊",
    layout="wide"
)

# Title and description
st.title("CSV Data Visualizer")
st.write("Upload your CSV file and explore the data through various visualizations")

# File upload
uploaded_file = st.file_uploader("Choose a CSV file", type="csv")

if uploaded_file is not None:
    # Load the data
    df = pd.read_csv(uploaded_file)
    
    # Display basic information about the dataset
    st.header("Dataset Overview")
    col1, col2, col3 = st.columns(3)
    with col1:
        st.write("Number of rows:", df.shape[0])
    with col2:
        st.write("Number of columns:", df.shape[1])
    with col3:
        st.write("Memory usage:", f"{df.memory_usage().sum() / 1024:.2f} KB")
    
    # Search and filter functionality
    st.subheader("Search and Filter")
    search_term = st.text_input("Search in any column:", "")
    
    # Create a mask for searching across all columns
    if search_term:
        mask = pd.DataFrame([df[col].astype(str).str.contains(search_term, case=False, na=False) 
                           for col in df.columns]).any()
        filtered_df = df[mask]
        st.write(f"Found {len(filtered_df)} rows containing '{search_term}'")
        st.dataframe(filtered_df)
    
    # Column-specific search
    st.subheader("Column-specific Search")
    col1, col2 = st.columns(2)
    with col1:
        search_column = st.selectbox("Select column to search:", df.columns)
    with col2:
        column_search_term = st.text_input("Search term:", key="column_search")
    
    if column_search_term:
        column_mask = df[search_column].astype(str).str.contains(column_search_term, case=False, na=False)
        column_filtered_df = df[column_mask]
        st.write(f"Found {len(column_filtered_df)} rows in column '{search_column}' containing '{column_search_term}'")
        st.dataframe(column_filtered_df)

    # Display the raw data with a toggle
    if st.checkbox("Show raw data"):
        st.subheader("Raw Data")
        st.dataframe(df)
    
    # Display basic statistics
    if st.checkbox("Show basic statistics"):
        st.subheader("Basic Statistics")
        st.write(df.describe())
    
    # Visualization options
    st.header("Visualizations")
    
    # Select columns for visualization
    numeric_cols = df.select_dtypes(include=['float64', 'int64']).columns
    categorical_cols = df.select_dtypes(include=['object', 'category']).columns
    
    # Scatter plot
    if len(numeric_cols) >= 2:
        st.subheader("Scatter Plot")
        x_col = st.selectbox("Select X axis", numeric_cols, key='scatter_x')
        y_col = st.selectbox("Select Y axis", numeric_cols, key='scatter_y')
        color_col = st.selectbox("Select color variable (optional)", 
                                ['None'] + list(df.columns), key='scatter_color')
        
        if color_col == 'None':
            fig = px.scatter(df, x=x_col, y=y_col)
        else:
            fig = px.scatter(df, x=x_col, y=y_col, color=color_col)
        st.plotly_chart(fig)
    
    # Histogram
    st.subheader("Histogram")
    hist_col = st.selectbox("Select column for histogram", numeric_cols)
    hist_bins = st.slider("Number of bins", min_value=5, max_value=50, value=20)
    
    fig = px.histogram(df, x=hist_col, nbins=hist_bins)
    st.plotly_chart(fig)
    
    # Box plot
    if len(categorical_cols) > 0 and len(numeric_cols) > 0:
        st.subheader("Box Plot")
        cat_col = st.selectbox("Select categorical column", categorical_cols)
        num_col = st.selectbox("Select numerical column", numeric_cols)
        
        fig = px.box(df, x=cat_col, y=num_col)
        st.plotly_chart(fig)
    
    # Correlation heatmap
    if len(numeric_cols) > 1:
        st.subheader("Correlation Heatmap")
        if st.checkbox("Show correlation heatmap"):
            corr = df[numeric_cols].corr()
            fig, ax = plt.subplots(figsize=(10, 8))
            sns.heatmap(corr, annot=True, cmap='coolwarm', ax=ax)
            st.pyplot(fig)
    
    # Missing values analysis
    st.subheader("Missing Values Analysis")
    if st.checkbox("Show missing values"):
        missing_data = df.isnull().sum()
        if missing_data.sum() > 0:
            missing_df = pd.DataFrame({
                'Column': missing_data.index,
                'Missing Values': missing_data.values,
                'Percentage': (missing_data.values / len(df) * 100).round(2)
            })
            st.write(missing_df)
            
            fig = px.bar(missing_df, x='Column', y='Percentage',
                        title='Percentage of Missing Values by Column')
            st.plotly_chart(fig)
        else:
            st.write("No missing values found in the dataset!")

else:
    st.info("Please upload a CSV file to begin visualization")

# Add footer
st.markdown("---")
st.markdown("Built with Streamlit by Your CSV Visualizer")